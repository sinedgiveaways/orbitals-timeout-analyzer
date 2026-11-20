using System.Buffers.Binary;
using System.Text;
using K4os.Compression.LZ4;

namespace OrbitalsCrashAnalyzer.Analysis;

public static class NsoAnalyzer
{
    private sealed record Segment(string Name, uint FileOffset, uint MemoryOffset, uint FileSize, uint MemorySize, bool Compressed, byte[] Data);

    public static string Analyze(string path)
    {
        var file = File.ReadAllBytes(path);
        if (file.Length < 0x30 || Encoding.ASCII.GetString(file, 0, 4) != "NSO0")
            throw new InvalidDataException("Le fichier ne possède pas un en-tête NSO0 valide.");

        uint flags = U32(file, 0x0C);
        var output = new StringBuilder();
        output.AppendLine($"[NSO] {path}");
        output.AppendLine($"Taille fichier : {file.Length:N0} octets | Flags : 0x{flags:X8}");
        var segments = new List<Segment>();
        string[] names = ["text", "rodata", "data"];
        for (int i = 0; i < 3; i++)
        {
            int h = 0x10 + i * 0x10;
            uint fileOffset = U32(file, h);
            uint memoryOffset = U32(file, h + 4);
            uint memorySize = U32(file, h + 8);
            uint fileSize = U32(file, 0x60 + i * 4);
            bool compressed = (flags & (1u << i)) != 0;
            if ((ulong)fileOffset + fileSize > (ulong)file.Length)
                throw new InvalidDataException($"Segment {names[i]} hors du fichier.");
            var packed = file.AsSpan((int)fileOffset, (int)fileSize).ToArray();
            byte[] data;
            if (compressed)
            {
                data = new byte[memorySize];
                int decoded = LZ4Codec.Decode(packed, 0, packed.Length, data, 0, data.Length);
                if (decoded != data.Length)
                    throw new InvalidDataException($"Décompression LZ4 de {names[i]} incomplète : {decoded}/{data.Length} octets.");
            }
            else
            {
                data = packed;
                if (data.Length != memorySize)
                    output.AppendLine($"AVERTISSEMENT : {names[i]} non compressé, taille fichier ({data.Length}) différente de taille mémoire ({memorySize}).");
            }
            segments.Add(new Segment(names[i], fileOffset, memoryOffset, fileSize, memorySize, compressed, data));
            output.AppendLine($"Segment {names[i],-6} : fichier=0x{fileOffset:X} taille-fichier=0x{fileSize:X} mémoire=0x{memoryOffset:X} taille-mémoire=0x{memorySize:X} {(compressed ? "LZ4" : "non compressé")}");
        }

        output.AppendLine();
        output.AppendLine("Recherche de marqueurs connus de l'analyse allocateur :");
        (string Name, byte[] Bytes)[] markers =
        [
            ("Metadata live 0x17EA5678", [0x78, 0x56, 0xEA, 0x17]),
            ("Metadata freed 0x39431234", [0x34, 0x12, 0x43, 0x39]),
            ("Allocator global 0x94C008B0", [0xB0, 0x08, 0xC0, 0x94]),
            ("Manager base 0x09072210", [0x10, 0x22, 0x07, 0x09])
        ];
        foreach (var marker in markers)
        {
            var locations = new List<string>();
            foreach (var seg in segments)
            {
                int from = 0;
                while (from <= seg.Data.Length - marker.Bytes.Length)
                {
                    int at = seg.Data.AsSpan(from).IndexOf(marker.Bytes);
                    if (at < 0) break;
                    int offset = from + at;
                    locations.Add($"{seg.Name}+0x{offset:X} (module+0x{seg.MemoryOffset + (uint)offset:X})");
                    from = offset + 1;
                    if (locations.Count >= 12) break;
                }
            }
            output.AppendLine($"  {marker.Name} : {(locations.Count == 0 ? "non trouvé" : string.Join("; ", locations))}");
        }
        output.AppendLine();
        output.AppendLine("Cette recherche est une recherche d'octets bruts : une valeur peut apparaître comme donnée, instruction ou constante sans être utilisée à l'exécution.");
        return output.ToString();
    }

    private static uint U32(byte[] data, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset, 4));
}
