import subprocess


def zafiyet_tara(hedef: str) -> str:
    """
    Nmap Scripting Engine (NSE) kullanarak hedefteki bilinen
    zafiyetleri (vulnerabilities) tarar.
    """
    print(f"\n[!] {hedef} için kritik zafiyet taraması başlatılıyor...")

    # --script vuln: Nmap'in en popüler zafiyet tarama kütüphanesidir.
    # Bu komut; smb-vuln, http-vuln gibi birçok scripti tek seferde çalıştırır.
    komut = ["nmap", "-sV", "--script=vuln", hedef]

    try:
        sonuc = subprocess.run(komut, capture_output=True, text=True, check=True)
        return sonuc.stdout
    except Exception as e:
        return f"[-] Tarama sırasında hata oluştu: {e}"
