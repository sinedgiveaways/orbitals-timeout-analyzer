using System.Text;

namespace OrbitalsCrashAnalyzer.Analysis;

public static class InvestigationProfile
{
    public static string Render()
    {
        var b = new StringBuilder();
        b.AppendLine("PROFIL D'ENQUÊTE PRÉCHARGÉ — CRASH B / TLS");
        b.AppendLine("Priorité : Crash B (access violation dans nn::os::GetTlsValue). Crash A / FMallocBinned3 est distinct et hors priorité.");
        b.AppendLine();
        b.AppendLine("[FAITS CONFIRMÉS PAR LES RAPPORTS DÉJÀ ANALYSÉS]");
        b.AppendLine("Exception : 0xC0000005 ; lecture à 0x104.");
        b.AppendLine("Hôte : orbitalgame+0x1B5B682F ; fonction levée : main+0x1759B20.");
        b.AppendLine("PC invité : sdk+0x16B730 (nn::os::GetTlsValue(TlsSlot)). LR : main+0x175A16C.");
        b.AppendLine("Instruction hôte : 42 8B 4C 01 5C 48 85 C9 ... ; décodage des 5 premiers octets : mov ecx,[rcx+r8+0x5c].");
        b.AppendLine("Avec RCX=0 et R8=0xA8, l'adresse effective vaut 0x104. La base hôte utilisée par cette lecture est nulle.");
        b.AppendLine("Code SDK connu à sdk+0x16B730 : MRS x8,TPIDRRO_EL0 ; LDR x8,[x8,#0x1F8] ; ADD x8,x8,w0,UXTW #3 ; LDR x0,[x8,#0x80] ; RET.");
        b.AppendLine("Frames invités : main+0x1750B88, +0x1750650, +0x1718CF8, +0x1D77D64, +0x1D761E0, +0x1641F84, puis +0x32A0C, +0x3348C, +0x4A688, +0x49E90, +0x16198B4, +0x1637DAC, +0x1C6AC ; sdk+0x169630, sdk+0x170B78.");
        b.AppendLine("Contexte observé dans un rapport : thread invité 0x254CC9A5000 ; TPIDR_EL0=0xA2003C740 ; TLR=0x7010078000 ; TLR[+0x1F8]=0x7C005A038.");
        b.AppendLine("Autre extrait : thread 0x2E1C6D9D880 ; TPIDR_EL0=0xA2003C740 ; TLR[+0x1F8]=0x7C0054038 ; chaîne x27 observée x27=0x840180400, [x27]=0.");
        b.AppendLine();
        b.AppendLine("[REPÈRES SDK À EXAMINER]");
        b.AppendLine("AllocateTlsSlot wrapper : sdk+0x16B670.");
        b.AppendLine("GetTlsValue : sdk+0x16B730.");
        b.AppendLine("TlsManager::SearchUnusedTlsSlotUnsafe : sdk+0x16C520.");
        b.AppendLine("Constructeurs TlsManager : sdk+0x16C7B0.");
        b.AppendLine("TlsManager::AllocateTlsSlot : sdk+0x16CC30.");
        b.AppendLine("Global TLS slot connu : main+0x8FF78F8 (cellule main+0x90100F8) ; initialisé au départ à 0xFFFFFFFF dans l'image statique.");
        b.AppendLine("Le wrapper d'initialisation est appelé depuis main+0x14090 ; sortie slot stockée via main+0x90100F8 ; destructeur main+0x1A820.");
        b.AppendLine("Le gestionnaire initialise count=0, mutex +0x108 et 32 slots destructeur ; allocation scanne 0..31 et appelle SetZeroToAllThreadsTlsSafe.");
        b.AppendLine();
        b.AppendLine("[QUESTIONS NON RÉSOLUES — NE PAS INVENTER DE CONCLUSION]");
        b.AppendLine("1. Quelle valeur de TlsSlot (w0) entre réellement dans GetTlsValue sur le chemin fautif ?");
        b.AppendLine("2. Quel objet thread est lu à TPIDRRO_EL0+0x1F8 à cet instant, et son tableau TLS couvre-t-il l'index ?");
        b.AppendLine("3. La base nulle apparaît-elle déjà dans l'état invité ou est-elle introduite par la traduction x86-64 / l'ABI du recomp runtime ?");
        b.AppendLine("4. Le pointeur ou le slot est-il invalide avant l'appel, ou s'agit-il d'une corruption antérieure ?");
        b.AppendLine();
        b.AppendLine("[HYPOTHÈSES OUVERTES]");
        b.AppendLine("A. Slot / contexte fourni invalide par l'appelant. B. Objet thread ou stockage TLS interne non initialisé. C. Défaut de traduction / mapping de registres / ABI. D. Corruption antérieure non encore démontrée.");
        b.AppendLine();
        b.AppendLine("[ORDRE D'ANALYSE]");
        b.AppendLine("1. Vérifier les arguments x0-x7 juste avant l'appel à sdk+0x16B730, sans confondre registres hôtes et invités.");
        b.AppendLine("2. Suivre w0/TlsSlot et la chaîne TPIDRRO_EL0 -> +0x1F8 -> objet thread -> +0x80 + slot*8.");
        b.AppendLine("3. Comparer l'état invité à l'adresse effective hôte et déterminer où la base devient nulle.");
        b.AppendLine("4. N'utiliser les fichiers main/sdk que pour compléter les données manquantes ; ne jamais lancer prepare.py ni recompiler le jeu pour cette analyse.");
        b.AppendLine();
        b.AppendLine("Statut : les faits ci-dessus sont des résultats antérieurs consignés, pas une preuve que l'analyseur a relu le log brut. Les hypothèses restent à départager.");
        return b.ToString();
    }
}
