# 🚀 ARP Spoofing & Paket Dinleme Aracı

🔹 Bu araç, **ARP spoofing** saldırıları yaparak ağ trafiğini manipüle etmeye ve **HTTP isteklerini dinlemeye** yarar. 
🔹 **Modüler bir yapı** sunar ve **terminal tabanlı bir kabuk (shell)** içerir.

---

## 🌟 Özellikler

✅ **ARP Spoofing**: Bireysel cihazlara veya tüm ağa yönelik saldırılar.  
✅ **📡 Paket Dinleme**: HTTP trafiğini analiz ederek veri yakalama.  
✅ **🖥️ MAC Adresi Değiştirme**: Cihazınızın MAC adresini değiştirme imkanı.  
✅ **💻 Terminal Kabuk Desteği**: Komut tabanlı yönetim ile kolay kullanım.  
✅ **🛠️ Ağ Onarma**: Saldırı sonrası ağın eski haline döndürülmesi.

---

## 📌 Kullanım

### 🔧 1. Kurulum

Gerekli kütüphaneleri yükleyin:

```bash
pip install -r requirements.txt
```

### 🚀 2. Aracı Çalıştırma

```bash
sudo python3 arp_emrenet.py
```

---

## 🛠️ Kullanılabilir Komutlar

### ⚡ **ARP Saldırıları**

```bash
arp.start <hedef_ip> <yanit_ip>    # 🎯 Belirli bir cihaza saldırı başlatır.
arp.stop <hedef_ip> <yanit_ip>     # 🛑 Belirli bir cihaza yapılan saldırıyı durdurur.
arp.durum                          # 📊 Aktif saldırıları ve gönderilen paket sayısını gösterir.
```

### 🌐 **Modem ve Tüm Ağa Saldırı**

```bash
arp.modem.start <modem_ip> <ip_araligi>   # 📡 Modeme ve ağa saldırı başlatır.
arp.modem.dur                             # 🔄 Saldırıyı durdurur ve ağı eski haline getirir.
arp.modem.durum                           # 📈 Saldırı durumu ve gönderilen paket sayısını gösterir.
```

### 🎧 **Paket Dinleme**

```bash
dinle.paket.basla <arayüz>    # 🔍 HTTP paketlerini dinlemeye başlar.
dinle.paket.durum            # 📡 Dinleme durumu ve yakalanan paketleri gösterir.
```

### 🔄 **MAC Değiştirme**

```bash
mac.changer <arayüz> <yeni_mac>   # 🔄 Cihazın MAC adresini değiştirir.
```

### 🛠️ **Genel Komutlar**

```bash
temizle    # 🧹 Terminali temizler.
exit       # 🚪 Kabuktan çıkar.
```

---

## ⚠️ Önemli Notlar

⚠️ Programın düzgün çalışması için **root** olarak çalıştırılmalıdır.  
⚠️ **Scapy** modülünün tüm özellikleri kullanılmaktadır.  
