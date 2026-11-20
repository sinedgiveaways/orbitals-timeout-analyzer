using System.Buffers.Binary;
using System.Text;
using K4os.Compression.LZ4;

internal static class Program
{
    private sealed record Section(string Name, uint FileOffset, uint DecompressedSize, uint MemoryOffset, bool Compressed);

    static int Main()
    {
        Console.OutputEncoding = Encoding.UTF8;
        Console.WriteLine("Orbitals TLS Crash Probe - Windows x64");
        Console.WriteLine("Analyse un SDK brut ou un fichier NSO et extrait les instructions ARM64 autour de GetTlsValue.");
        Console.WriteLine();

        Console.Write("Chemin du fichier SDK (ou NSO) : ");
        var path = (Console.ReadLine() ?? "").Trim().Trim('"');
        if (!File.Exists(path)) { Console.WriteLine("Fichier introuvable."); return 2; }

        Console.Write("Offset cible dans le module (défaut 0x16B6D0) : ");
        var offsetText = (Console.ReadLine() ?? "").Trim();
        if (string.IsNullOrWhiteSpace(offsetText)) offsetText = "0x16B6D0";
        if (!TryHex(offsetText, out ulong target)) { Console.WriteLine("Offset invalide."); return 2; }

        Console.Write("Nombre d'octets avant/après (défaut 0x80) : ");
        var spanText = (Console.ReadLine() ?? "").Trim();
        if (string.IsNullOrWhiteSpace(spanText)) spanText = "0x80";
        if (!TryHex(spanText, out ulong span) || span > 0x1000) { Console.WriteLine("Plage invalide (maximum 0x1000)."); return 2; }

        try
        {
            var file = File.ReadAllBytes(path);
            byte[] image;
            string sectionName;
            ulong sectionBase;
            if (file.Length >= 4 && Encoding.ASCII.GetString(file, 0, 4) == "NSO0")
            {
                var sections = ReadNso(file);
                var text = sections.FirstOrDefault(s => s.Name == "TEXT") ?? throw new InvalidDataException("Section TEXT absente du NSO.");
                image = ExtractSection(file, text);
                sectionName = "NSO TEXT";
                sectionBase = text.MemoryOffset;
                Console.WriteLine($"NSO détecté. TEXT: fichier+0x{text.FileOffset:X}, mémoire+0x{text.MemoryOffset:X}, taille décompressée=0x{image.Length:X}.");
                Console.WriteLine("L'offset saisi est interprété comme un offset relatif au début de TEXT.");
            }
            else
            {
                image = file;
                sectionName = "binaire brut";
                sectionBase = 0;
                Console.WriteLine($"Binaire brut : {image.Length:N0} octets. Offset interprété depuis le début du fichier.");
            }

            if (target >= (ulong)image.Length) throw new InvalidDataException($"Offset 0x{target:X} hors fichier/section (taille 0x{image.Length:X}).");
            int start = (int)(target > span ? target - span : 0);
            int end = (int)Math.Min((ulong)image.Length, target + span);
            start = (start + 3) & ~3;
            end &= ~3;

            var report = new StringBuilder();
            report.AppendLine("ORBITALS TLS CRASH PROBE");
            report.AppendLine($"Fichier : {Path.GetFullPath(path)}");
            report.AppendLine($"Type : {sectionName}");
            report.AppendLine($"Cible relative : 0x{target:X}");
            report.AppendLine($"Adresse mémoire NSO (si connue) : 0x{sectionBase + target:X}");
            report.AppendLine($"Fenêtre : 0x{start:X}..0x{end:X}");
            report.AppendLine();
            report.AppendLine("OFFSET       BYTES        ARM64 (décodage partiel)");
            report.AppendLine("--------------------------------------------------");

            for (int p = start; p + 4 <= end; p += 4)
            {
                uint ins = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(p, 4));
                report.AppendLine($"{p:X8}     {ins:X8}     {Decode(ins, (ulong)p)}");
            }

            report.AppendLine();
            report.AppendLine("OCTETS BRUTS (copie intégrale de la fenêtre)");
            report.AppendLine(Convert.ToHexString(image.AsSpan(start, end - start)));
            var outPath = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(path))!, "orbitals_tls_probe.txt");
            File.WriteAllText(outPath, report.ToString(), new UTF8Encoding(false));
            Console.WriteLine();
            Console.WriteLine("Analyse terminée : " + outPath);
            Console.WriteLine("Ouvre ce fichier et colle son contenu ici.");
            return 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine("Erreur : " + ex.Message);
            return 1;
        }
    }

    private static bool TryHex(string value, out ulong result)
    {
        value = value.Trim();
        if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) value = value[2..];
        return ulong.TryParse(value, System.Globalization.NumberStyles.HexNumber, null, out result);
    }

    private static List<Section> ReadNso(byte[] b)
    {
        if (b.Length < 0x100) throw new InvalidDataException("En-tête NSO tronqué.");
        uint flags = U32(b, 0x0C);
        var result = new List<Section>();
        Add("TEXT", 0x10, 0x18, 0x20, 1);
        Add("RODATA", 0x28, 0x30, 0x38, 2);
        Add("DATA", 0x40, 0x48, 0x50, 4);
        return result;

        void Add(string name, int filePos, int sizePos, int memPos, int bit)
        {
            uint off = U32(b, filePos), size = U32(b, sizePos), mem = U32(b, memPos);
            if ((ulong)off + size > (ulong)b.Length) throw new InvalidDataException($"Section {name} dépasse le fichier.");
            result.Add(new Section(name, off, size, mem, (flags & bit) != 0));
        }
    }

    private static byte[] ExtractSection(byte[] file, Section s)
    {
        var src = file.AsSpan((int)s.FileOffset, (int)s.DecompressedSize).ToArray();
        if (!s.Compressed) return src;
        // NSO stores compressed size at the section's file-offset field + 4 in the module header.
        // The caller's Section uses the header's stored file size separately in normal NSO layouts.
        throw new InvalidDataException("Section NSO compressée détectée. Cette version attend un SDK décompressé ou un NSO non compressé; fournis le fichier extrait si le NSO est compressé.");
    }

    private static uint U32(byte[] b, int p) => BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(p, 4));

    private static string Decode(uint x, ulong pc)
    {
        uint rd=x&31, rn=(x>>5)&31, rm=(x>>16)&31;
        if (x == 0xD503237F) return "PACIBSP";
        if (x == 0xD503233F) return "PACIASP";
        if ((x & 0xFC000000) == 0x94000000) return $"BL 0x{(long)pc + Sign(x & 0x03FFFFFF,26)*4:X}";
        if ((x & 0xFC000000) == 0x14000000) return $"B 0x{(long)pc + Sign(x & 0x03FFFFFF,26)*4:X}";
        if ((x & 0x9F000000) == 0x90000000)
        {
            long imm = Sign((((long)(x>>5)&0x7FFFF)<<2) | ((x>>29)&3),21) << 12;
            return $"ADRP X{rd}, 0x{((long)pc & ~0xFFF)+imm:X}";
        }
        if ((x & 0x7F000000) == 0x11000000) return $"ADD{((x>>31)!=0?"S":"")} {(x>>31)!=0?"W":"X"}{rd}, {(x>>31)!=0?"W":"X"}{rn}, #0x{(((x>>10)&0xFFF) << (((x>>22)&1)!=0?12:0)):X}";
        if ((x & 0x7F200000) == 0x0B000000) return $"ADD {(x>>31)!=0?"X":"W"}{rd}, {(x>>31)!=0?"X":"W"}{rn}, {(x>>31)!=0?"X":"W"}{rm}";
        if ((x & 0xFFC00000) == 0xF9400000) return $"LDR X{rd}, [X{rn}, #0x{((x>>10)&0xFFF)*8:X}]";
        if ((x & 0xFFC00000) == 0xB9400000) return $"LDR W{rd}, [X{rn}, #0x{((x>>10)&0xFFF)*4:X}]";
        if ((x & 0xFFC00000) == 0xF9000000) return $"STR X{rd}, [X{rn}, #0x{((x>>10)&0xFFF)*8:X}]";
        if ((x & 0xFFC00000) == 0xB9000000) return $"STR W{rd}, [X{rn}, #0x{((x>>10)&0xFFF)*4:X}]";
        if ((x & 0xFFE0FC00) == 0xAA0003E0) return $"MOV X{rd}, X{rm}";
        if ((x & 0x7FE0FC00) == 0x2A0003E0) return $"MOV W{rd}, W{rm}";
        if ((x & 0x7F000000) == 0x34000000) return $"{((x>>24)&1)==0?"CBZ":"CBNZ"} {(x>>31)!=0?"X":"W"}{rd}, 0x{(long)pc+Sign((x>>5)&0x7FFFF,19)*4:X}";
        if ((x & 0x7E000000) == 0x36000000) return $"{((x>>24)&1)==0?"TBZ":"TBNZ"} {(x>>31)!=0?"X":"W"}{rd}, #{((x>>19)&0x1F)|((x>>26)&0x20)}, 0x{(long)pc+Sign((x>>5)&0x3FFF,14)*4:X}";
        if ((x & 0x7F000000) == 0x71000000) return $"CMP W{rn}, #0x{(x>>10)&0xFFF:X}";
        if ((x & 0x7F000000) == 0xF1000000) return $"CMP X{rn}, #0x{(x>>10)&0xFFF:X}";
        if ((x & 0xFFFFFC1F) == 0xD65F0000) return $"RET X{rn}";
        if ((x & 0xFFC003E0) == 0xA94003E0) return $"LDP X{rd}, X{rm}, [X{rn}]";
        if ((x & 0xFFC003E0) == 0xA90003E0) return $"STP X{rd}, X{rm}, [X{rn}]";
        return ".word 0x" + x.ToString("X8");
    }

    private static long Sign(uint v, int bits) => (long)(v << (32-bits)) >> (32-bits);
}