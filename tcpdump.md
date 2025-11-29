## 📡 tcpdump Nedir? Sıfırdan Tam Eğitim (Flag Odaklı)

Bu doküman, **hiç tcpdump bilmeyen birinin** adım adım okuyup:

- **tcpdump'un ne olduğunu**,
- **TÜM flag'lerin ne işe yaradığını**,
- **Ne zaman hangi flag'i kullanacağını**,
- **Pratik senaryolarda nasıl kullanılacağını**

tam olarak anlayabilmesi için hazırlanmıştır. **Kurulum değil, flag'ler ve kullanım senaryoları** odaklıdır.

---

## 🔎 1. tcpdump Nedir?

**tcpdump**, Linux/Unix sistemlerde **komut satırından ağ trafiğini yakalama ve analiz etme** aracıdır.

- **Paket yakalama (packet capture)** yapar.
- **libpcap** kütüphanesini kullanır (Wireshark'ın da arka planında aynı kütüphane var).
- **Real-time** veya **offline (PCAP dosyası)** analiz yapabilir.
- **Filtreleme** ile sadece istediğin trafiği yakalayabilirsin.

**Kullanım Alanları:**
- Ağ trafiğini debug etmek
- Saldırı analizi (IDS/IPS logları ile birlikte)
- Network troubleshooting
- Trafik analizi ve istatistik
- PCAP dosyası oluşturup Wireshark'ta analiz etmek

---

## 🧩 2. tcpdump'un Temel Çalışma Mantığı

1. **Paket Yakalama**: Seçtiğin interface'ten (eth0, wlan0 vb.) paketleri yakalar.
2. **Filtreleme**: BPF (Berkeley Packet Filter) syntax ile filtreleme yapar.
3. **Çıktı**: Terminalde gösterir veya dosyaya kaydeder.

**Temel Komut Yapısı:**
```bash
tcpdump [flag'ler] [BPF filtresi]
```

---

## 🚦 3. Temel Kullanım (Hızlı Başlangıç)

### 3.1. Tüm Trafiği Görmek
```bash
tcpdump -i eth0
```

### 3.2. Belirli Bir Portu Dinlemek
```bash
tcpdump -i eth0 port 80
```

### 3.3. PCAP Dosyasına Kaydetmek
```bash
tcpdump -i eth0 -w capture.pcap
```

### 3.4. PCAP Dosyasını Okumak
```bash
tcpdump -r capture.pcap
```

---

## 🧾 4. tcpdump Flag'leri – Detaylı Açıklamalar

### 4.1. INTERFACE ve YAKALAMA Flag'leri

#### `-i <interface>`
**Ne İşe Yarar:** Dinlenecek ağ arayüzünü belirtir.

**Ne Zaman Kullanılır:**
- Belirli bir interface'ten trafik yakalamak istediğinde
- Birden fazla interface varsa hangisini dinleyeceğini seçmek için
- `any` yazarsan tüm interface'leri dinler

**Örnekler:**
```bash
# eth0 interface'ini dinle
tcpdump -i eth0

# wlan0 (WiFi) interface'ini dinle
tcpdump -i wlan0

# Tüm interface'leri dinle
tcpdump -i any

# ens33 interface'ini dinle (modern Linux)
tcpdump -i ens33
```

**Not:** Interface ismini bilmiyorsan `ip link show` veya `ifconfig` komutlarıyla öğrenebilirsin.

---

#### `-D` veya `--list-interfaces`
**Ne İşe Yarar:** Sistemdeki tüm ağ interface'lerini listeler.

**Ne Zaman Kullanılır:**
- Hangi interface'lerin mevcut olduğunu görmek için
- Interface ismini unuttuğunda

**Örnek:**
```bash
tcpdump -D
# Çıktı:
# 1.eth0
# 2.wlan0
# 3.any
# 4.lo
```

---

#### `-p` veya `--no-promiscuous-mode`
**Ne İşe Yarar:** Promiscuous mode'u kapatır (varsayılan olarak açıktır).

**Ne Zaman Kullanılır:**
- Sadece kendi makineye gelen/giden trafiği görmek istediğinde
- Switch üzerinde çalışıyorsan ve diğer hostların trafiğini görmek istemiyorsan

**Örnek:**
```bash
# Sadece kendi trafiğini yakala
tcpdump -i eth0 -p # bu cihaza ait olmayan trafiği gösterme
```

**Not:** Promiscuous mode açıkken, interface tüm trafiği yakalar (switch'teki diğer hostların trafiği de dahil).

---

#### `-s <snaplen>` veya `--snapshot-length=<snaplen>`
**Ne İşe Yarar:** Her paketten yakalanacak byte sayısını belirler.

**Ne Zaman Kullanılır:**
- Büyük paketlerin sadece header'larını görmek istediğinde (performans için)
- Tam payload'u görmek istediğinde (büyük değer veya 0)

**Örnekler:**
```bash
# Sadece ilk 64 byte'ı yakala (header'lar için yeterli)
tcpdump -i eth0 -s 64

# Sadece ilk 128 byte'ı yakala
tcpdump -i eth0 -s 128

# Tüm paketi yakala (0 = sınırsız)
tcpdump -i eth0 -s 0

# Varsayılan: 262144 byte (yaklaşık 256 KB)
```

**Not:** `-s 0` tüm paketi yakalar ama performansı düşürebilir. Genelde `-s 0` veya `-s 65535` kullanılır.

---

### 4.2. ÇIKTI ve FORMAT Flag'leri

#### `-v`, `-vv`, `-vvv` (Verbose)
**Ne İşe Yarar:** Çıktının detay seviyesini artırır.

**Ne Zaman Kullanılır:**
- Daha fazla bilgi görmek istediğinde
- TTL, ID, tos, window size gibi IP/TCP detaylarını görmek için
- Debug yaparken

**Örnekler:**
```bash
# Normal detay
tcpdump -i eth0 -v

# Daha fazla detay (IP header detayları)
tcpdump -i eth0 -vv

# Maksimum detay (tüm header bilgileri)
tcpdump -i eth0 -vvv
```

**Çıktı Farkı:**
- `-v`: TTL, ID, length gibi IP bilgileri
- `-vv`: IP options, TCP options
- `-vvv`: Paket içeriği (hex/ASCII)

---

#### `-n`
**Ne İşe Yarar:** DNS çözümlemesi yapmaz, IP adreslerini direkt gösterir.

**Ne Zaman Kullanılır:**
- Hızlı çıktı istediğinde (DNS lookup yapmaz, daha hızlı)
- IP adreslerini direkt görmek istediğinde
- Production ortamlarında (DNS lookup gereksiz yük oluşturur)

**Örnek:**
```bash
# DNS çözümlemesi YOK (hızlı)
tcpdump -i eth0 -n

# DNS çözümlemesi VAR (yavaş ama hostname gösterir)
tcpdump -i eth0
```

**Karşılaştırma:**
```bash
# -n OLMADAN: "google.com" gösterir
# -n İLE: "8.8.8.8" gösterir
```

---

#### `-nn`
**Ne İşe Yarar:** Hem DNS çözümlemesi yapmaz hem de port numaralarını isimlere çevirmez.

**Ne Zaman Kullanılır:**
- Hem IP hem port numaralarını direkt görmek istediğinde
- En hızlı çıktı için

**Örnek:**
```bash
# IP ve port numaralarını direkt göster
tcpdump -i eth0 -nn
```

**Karşılaştırma:**
- Normal: `google.com.http` gösterir
- `-n`: `8.8.8.8.http` gösterir
- `-nn`: `8.8.8.8.80` gösterir

---

#### `-N`
**Ne İşe Yarar:** Hostname'lerin domain kısmını göstermez.

**Ne Zaman Kullanılır:**
- Sadece hostname'i görmek istediğinde (domain olmadan)

**Örnek:**
```bash
tcpdump -i eth0 -N
# "www" gösterir, "www.google.com" değil
```

---

#### `-q` veya `--quick`
**Ne İşe Yarar:** Kısa (quiet) çıktı üretir, daha az bilgi gösterir.

**Ne Zaman Kullanılır:**
- Sadece temel bilgileri görmek istediğinde
- Çok fazla trafik varsa ve özet istiyorsan

**Örnek:**
```bash
tcpdump -i eth0 -q
```

---

#### `-t`
**Ne İşe Yarar:** Timestamp göstermez.

**Ne Zaman Kullanılır:**
- Timestamp'e ihtiyaç olmadığında
- Daha temiz çıktı için

**Örnek:**
```bash
tcpdump -i eth0 -t
```

---

#### `-tt`
**Ne İşe Yarar:** Timestamp'i epoch formatında (Unix timestamp) gösterir.

**Ne Zaman Kullanılır:**
- Zamanı script'lerde kullanmak için
- Log analizinde zaman hesaplamaları için

**Örnek:**
```bash
tcpdump -i eth0 -tt
# Çıktı: 1704067200.123456 IP 192.168.1.10 > 8.8.8.8: ...
```

---

#### `-ttt`
**Ne İşe Yarar:** Her paket arasındaki zaman farkını (delta) gösterir.

**Ne Zaman Kullanılır:**
- Paketler arası zamanlama analizi için
- Network latency analizi için

**Örnek:**
```bash
tcpdump -i eth0 -ttt
# Çıktı: 00:00:00.001234 IP 192.168.1.10 > 8.8.8.8: ...
```

---

#### `-tttt`
**Ne İşe Yarar:** Timestamp'i okunabilir formatta (YYYY-MM-DD HH:MM:SS) gösterir.

**Ne Zaman Kullanılır:**
- İnsan tarafından okunabilir zaman formatı istediğinde
- Log dosyalarında zamanı net görmek için

**Örnek:**
```bash
tcpdump -i eth0 -tttt
# Çıktı: 2024-01-01 12:34:56.123456 IP 192.168.1.10 > 8.8.8.8: ...
```

---
## 🔹 **-t : Timestamp’i tamamen kaldırır**

Çıktıda **zaman bilgisi görünmez**.  
Hızlı ve sade analiz için kullanılır.

---

## 🔹 **-tt : UNIX epoch zamanını gösterir**

Timestamp’i **1970’ten itibaren geçen saniye ve mikro-saniye** olarak verir.

Örnek:

`1719761234.123456`

Bu format genellikle:

- Olay korelasyonu,
    
- Programatik log eşleşmesi,
    
- Script ile paket analizinde  
    kullanılır.
    

---

## 🔹 **-ttt : Paketler arası zaman farkını gösterir**

Timestamp yerine **bir önceki paket ile bu paket arasındaki süreyi** yazar.

Örnek:

`0.000345 1.234500 0.000112`

Bu sana şunları gösterir:

- Ağda gecikme var mı?
    
- Paketler arasındaki boşluk ne kadar?
    
- Flood/DDOS benzeri “çok hızlı akan trafik” var mı?
    

TH / Network Forensics için çok faydalıdır.

---

## 🔹 **-tttt : Tam tarih + saat gösterir**

Bu en detaylı timestamp’tir.

Örnek:

`2025-11-29 14:22:10.123456`

Bu format genelde:

- Olay zaman çizelgesinde,
    
- Loglarla eşleştirmede (SIEM, syslog, firewall),
    
- IR (Incident Response) analizlerinde  
    kullanılır.
------------------------

#### `-X`
**Ne İşe Yarar:** Paket içeriğini hem HEX hem ASCII formatında gösterir.

**Ne Zaman Kullanılır:**
- Paket payload'unu incelemek için
- Exploit analizi için
- Application layer verisini görmek için

**Örnek:**
```bash
tcpdump -i eth0 -X
# Çıktı:
# 0x0000:  4500 003c 1c46 4000 4006 b1e6 c0a8 010a
# 0x0010:  0808 0808 0014 0050 0000 0000 0000 0000
#          E...<..F@.@.......
#          .........P........
```

---

#### `-XX`
**Ne İşe Yarar:** Paket içeriğini HEX ve ASCII formatında gösterir, **Ethernet header dahil**.

**Ne Zaman Kullanılır:**
- Layer 2 (Ethernet) header'ını da görmek istediğinde
- MAC adreslerini görmek için

**Örnek:**
```bash
tcpdump -i eth0 -XX
```

---
## 🔹 **-a : Ağ adreslerini isim çözümlemesi yaparak gösterir (address-to-name resolution)**

Yani -a kullanırsan tcpdump:

- IP adreslerini → hostname’e
    
- Port numaralarını → servis ismine  
    çevirmeye çalışır.
    

### Örnek (çözümleme kapalıyken):

`192.168.1.10.443 > 192.168.1.20.51532`

### Örnek (-a açıkken):

`server.local.https > client.local.ephemeral`

tcpdump **DNS veya /etc/services** bilgilerini kullanarak daha okunabilir isimler üretir.

---

## 🔹 Ne zaman kullanılır? (Siber güvenlik bakışı)

- Analiz edeceğin ağ trafiği küçükse, okunabilirlik artsın diye
    
- Yerel ağda hostname’ler senin için anlamlıysa
    
- Logları daha insani bir formatta görmen gerekiyorsa
- -------------------

#### `-A`
**Ne İşe Yarar:** Paket içeriğini sadece ASCII formatında gösterir (HTTP, SMTP gibi text protokoller için ideal).

**Ne Zaman Kullanılır:**
- HTTP trafiğini okumak için
- SMTP/email trafiğini görmek için
- Text tabanlı protokolleri analiz etmek için

**Örnek:**
```bash
# HTTP trafiğini ASCII olarak göster
tcpdump -i eth0 -A port 80
```

**Çıktı Örneği:**
```
GET /index.html HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0
```

---

#### `-x`
**Ne İşe Yarar:** Paket içeriğini sadece HEX formatında gösterir (header dahil, ASCII yok).

**Ne Zaman Kullanılır:**
- HEX formatında paket analizi için
- Binary veriyi görmek için

**Örnek:**
```bash
tcpdump -i eth0 -x
```

---

#### `-xx`
**Ne İşe Yarar:** Paket içeriğini HEX formatında gösterir, **Ethernet header dahil**.

**Ne Zaman Kullanılır:**
- Layer 2 header'ı ile birlikte HEX görmek için

**Örnek:**
```bash
tcpdump -i eth0 -xx
```

---

### 4.3. DOSYA İŞLEMLERİ Flag'leri

#### `-w <file>` veya `--write-file=<file>`
**Ne İşe Yarar:** Yakalanan paketleri PCAP dosyasına kaydeder.

**Ne Zaman Kullanılır:**
- Trafiği daha sonra analiz etmek için kaydetmek istediğinde
- Wireshark'ta analiz etmek için PCAP oluşturmak
- Uzun süreli trafik yakalama için

**Örnekler:**
```bash
# Trafiği capture.pcap dosyasına kaydet
tcpdump -i eth0 -w capture.pcap

# Belirli bir portu kaydet
tcpdump -i eth0 -w http.pcap port 80

# Tüm trafiği kaydet (filtre yok)
tcpdump -i any -w all_traffic.pcap
```

**Not:** PCAP dosyası binary formatındadır, Wireshark, tcpdump, Snort, Suricata gibi araçlarla açılabilir.

---

#### `-r <file>` veya `--read-file=<file>`
**Ne İşe Yarar:** PCAP dosyasını okuyup analiz eder (offline analiz).

**Ne Zaman Kullanılır:**
- Daha önce kaydedilmiş PCAP dosyasını analiz etmek için
- Wireshark'tan export edilmiş PCAP'i tcpdump ile okumak
- Offline trafik analizi için

**Örnekler:**
```bash
# PCAP dosyasını oku
tcpdump -r capture.pcap

# PCAP'i oku ve filtrele
tcpdump -r capture.pcap port 80

# PCAP'i oku ve detaylı göster
tcpdump -r capture.pcap -A -X

# PCAP'i oku ve başka dosyaya yaz
tcpdump -r input.pcap -w output.pcap port 443
```

---

#### `-W <count>`
**Ne İşe Yarar:** PCAP dosyası sayısını sınırlar (rotation için).

**Ne Zaman Kullanılır:**
- Çok sayıda PCAP dosyası oluşturmak istediğinde
- Dosya rotation yapmak için

**Örnek:**
```bash
# 10 dosya oluştur, her biri 100 MB
tcpdump -i eth0 -w capture.pcap -W 10 -C 100
```

---

#### `-C <size>`
**Ne İşe Yarar:** PCAP dosyası boyutunu MB cinsinden sınırlar (dosya büyüyünce yeni dosya oluşturur).

**Ne Zaman Kullanılır:**
- Çok büyük PCAP dosyaları oluşturmamak için
- Disk alanını yönetmek için
- Dosya rotation için

**Örnekler:**
```bash
# Her 100 MB'da yeni dosya oluştur
tcpdump -i eth0 -w capture.pcap -C 100

# Her 10 MB'da yeni dosya oluştur
tcpdump -i eth0 -w capture.pcap -C 10
```

**Not:** Dosyalar `capture.pcap`, `capture.pcap1`, `capture.pcap2` şeklinde numaralanır.

---

#### `-G <seconds>`
**Ne İşe Yarar:** Belirli saniye aralıklarında yeni PCAP dosyası oluşturur (zaman bazlı rotation).

**Ne Zaman Kullanılır:**
- Zaman bazlı dosya rotation için
- Her saat/dakika yeni dosya oluşturmak için

**Örnekler:**
```bash
# Her 3600 saniyede (1 saat) yeni dosya
tcpdump -i eth0 -w capture_%H%M%S.pcap -G 3600

# Her 60 saniyede yeni dosya
tcpdump -i eth0 -w capture.pcap -G 60
```

**Not:** `-G` ile `-w` içinde zaman formatı kullanabilirsin: `%H` (saat), `%M` (dakika), `%S` (saniye).

---

#### `-U` veya `--packet-buffered`
**Ne İşe Yarar:** Her paketi hemen dosyaya yazar (buffer'lamaz).

**Ne Zaman Kullanılır:**
- Real-time analiz için
- Paket kaybını önlemek için
- Kritik trafik yakalarken

**Örnek:**
```bash
tcpdump -i eth0 -w capture.pcap -U
```

**Not:** Performansı biraz düşürebilir ama paket kaybı riskini azaltır.

---

### 4.4. FİLTRELEME ve SAYMA Flag'leri

#### `-c <count>`
**Ne İşe Yarar:** Belirli sayıda paket yakaladıktan sonra durur.

**Ne Zaman Kullanılır:**
- Sadece birkaç paket görmek istediğinde
- Test için
- Script'lerde otomatik durdurmak için

**Örnekler:**
```bash
# 10 paket yakala ve dur
tcpdump -i eth0 -c 10

# 100 paket yakala ve dur
tcpdump -i eth0 -c 100 port 80

# İlk 5 ICMP paketini yakala
tcpdump -i eth0 -c 5 icmp
```

---

#### `-K` veya `--dont-verify-checksums`
**Ne İşe Yarar:** Checksum doğrulamasını yapmaz.

**Ne Zaman Kullanılır:**
- Offload edilmiş checksum'lar nedeniyle hatalı görünen paketleri yakalamak için
- Network kartı checksum offload kullanıyorsa

**Örnek:**
```bash
tcpdump -i eth0 -K
```

**Not:** Modern network kartları checksum'ı hardware'de yapar, bu yüzden tcpdump bazen checksum hatası gösterir. `-K` ile bu uyarıları kapatırsın.
## 🔹 `-K` Ne İşe Yarar?

`-K`, **TCP checksum doğrulamasını kapatır**.

Normalde tcpdump paketleri yakalarken TCP header içindeki **checksum değerini kontrol eder**.  
Checksum hatalıysa sana “checksum error” diye gösterebilir.

Ama bazen:

- NAT
    
- offloading
    
- virtual interface
    
- donanımsal hızlandırma
    
- container / VM ağları
    

gibi şeyler yüzünden paket **henüz hesaplanmamış** veya **yanlış görünebilir**.  
Bu da gereksiz uyarılara sebep olur.

İşte böyle durumlarda:

`tcpdump -K`

dediğinde tcpdump şöyle davranır:

➡️ **TCP checksum’u kontrol etmez**  
➡️ **Hatalı görünse bile paketleri normal gösterir**  
➡️ Offloading yüzünden yanlış “checksum error” uyarılarını susturur

---

### 4.5. PROTOKOL ve LAYER Flag'leri

#### `-e`
**Ne İşe Yarar:** Ethernet (Layer 2) header bilgilerini gösterir (MAC adresleri).

**Ne Zaman Kullanılır:**
- MAC adreslerini görmek için
- Layer 2 analizi için
- ARP trafiğini analiz etmek için

**Örnek:**
```bash
tcpdump -i eth0 -e
# Çıktı: 00:11:22:33:44:55 > aa:bb:cc:dd:ee:ff, ethertype IPv4 (0x0800), ...
```

---

#### `-l` veya `--immediate-mode`
**Ne İşe Yarar:** Çıktıyı line-buffered yapar (her satırı hemen gösterir).

**Ne Zaman Kullanılır:**
- Pipe ile başka komutlara gönderirken
- Real-time görüntüleme için

**Örnek:**
```bash
# Grep ile filtrele
tcpdump -i eth0 -l | grep "GET"

# Tee ile hem ekrana hem dosyaya
tcpdump -i eth0 -l | tee output.txt
```

---

#### `-S` veya `--absolute-tcp-sequence-numbers`
**Ne İşe Yarar:** TCP sequence numaralarını relative değil, absolute gösterir.

**Ne Zaman Kullanılır:**
- TCP sequence analizi için
- Network debugging için

**Örnek:**
```bash
tcpdump -i eth0 -S
```

---

#### `-F <file>`
**Ne İşe Yarar:** BPF filtresini dosyadan okur.

**Ne Zaman Kullanılır:**
- Karmaşık filtreleri dosyada saklamak için
- Aynı filtreyi tekrar kullanmak için

**Örnek:**
```bash
# filter.txt içinde: "port 80 or port 443"
tcpdump -i eth0 -F filter.txt
```

---

#### `-d`
**Ne İşe Yarar:** BPF filtresinin derlenmiş kodunu gösterir.

**Ne Zaman Kullanılır:**
- Filtrenin nasıl çalıştığını anlamak için
- Debug için

**Örnek:**
```bash
tcpdump -d port 80
```

---

#### `-dd`
**Ne İşe Yarar:** BPF filtresini C programı formatında gösterir.

**Ne Zaman Kullanılır:**
- Programatik kullanım için

**Örnek:**
```bash
tcpdump -dd port 80
```

---

#### `-ddd`
**Ne İşe Yarar:** BPF filtresini sayısal formatta gösterir.

**Ne Zaman Kullanılır:**
- Low-level analiz için

**Örnek:**
```bash
tcpdump -ddd port 80
```
## 🔹 tcpdump’da `-d`, `-dd`, `-ddd`

Bu seçenekler **BPF (Berkeley Packet Filter) kodunu gösterir**, debug değildir. Ama seviyeleri vardır:

| Seçenek  | Ne yapar?                                                                        |
| -------- | -------------------------------------------------------------------------------- |
| **-d**   | Filtreyi insanın okuyabileceği “assembly benzeri” formda gösterir                |
| **-dd**  | Filtreyi **C array** formatında gösterir, program içine gömülebilir              |
| **-ddd** | Filtreyi **saf sayılar listesi** olarak gösterir (kernel’e doğrudan verilebilir) |

---

### 4.6. DİĞER ÖNEMLİ Flag'ler

#### `-Z <user>` veya `--relinquish-privileges=<user>`
**Ne İşe Yarar:** Root olarak başladıktan sonra belirtilen kullanıcıya geçer (güvenlik için).

**Ne Zaman Kullanılır:**
- Güvenlik best practice için
- Production ortamlarında

**Örnek:**
```bash
sudo tcpdump -i eth0 -Z nobody
```

---

#### `-y <type>` veya `--linktype=<type>`
**Ne İşe Yarar:** Paket tipini belirtir (varsayılan: otomatik tespit).

**Ne Zaman Kullanılır:**
- Özel link tipleri için
- Tunnel trafiği için

**Örnek:**
```bash
tcpdump -i eth0 -y EN10MB
```
## 🔹 **-y ne yapar?**

Normalde tcpdump arayüzün link-layer türünü otomatik algılar (örneğin Ethernet: `EN10MB`).

Ama bazı durumlarda bunu **manuel** seçmek istersin.

Kullanımı:

`tcpdump -y <linktype>`

---

## 🔹 En yaygın link-type örnekleri

|Link-type|Açıklama|
|---|---|
|**EN10MB**|Ethernet (en yaygın)|
|**RAW**|Header’sız raw IP paketleri|
|**IEEE802_11**|Wireless (Wi-Fi)|
|**PPP**|Point-to-Point Protocol (VPN, tüneller)|
|**LINUX_SLL**|Linux “cooked” capture (tun/tap arayüzlerinde)|
---

#### `-L` veya `--list-data-link-types`
**Ne İşe Yarar:** Desteklenen link tiplerini listeler.

**Ne Zaman Kullanılır:**
- Hangi link tiplerinin mevcut olduğunu görmek için

**Örnek:**
```bash
tcpdump -L
```

---

#### `-B <buffer_size>`
**Ne İşe Yarar:** Kernel buffer boyutunu KB cinsinden belirler.

**Ne Zaman Kullanılır:**
- Yüksek trafikli ortamlarda paket kaybını önlemek için
- Buffer boyutunu artırmak için

**Örnek:**
```bash
# 1 MB buffer
tcpdump -i eth0 -B 1024
```
## 🌟 Benzetme ile anlatım:

Düşün ki ağdan bir nehir gibi paketler geliyor.

- tcpdump → paketi yakalayıp kaydedecek kişi.
    
- Kernel buffer → tcpdump’ın paketleri alana kadar beklediği **küçük bir sepet**.
    

### Normal durum:

- Sepet küçük → çok hızlı paket gelirse sepet doluyor → bazı paketler **düşüyor**, kayboluyor.
    

### -B ile:

- Sepeti büyütüyorsun → tcpdump daha çok paketi tutabilir → **daha az paket kaybı**.
    

---

## 🔹 Örnek

`tcpdump -B 4096`

- 4096 KB’lık buffer (yaklaşık 4 MB)
    
- Paketler burada tutulur, tcpdump yetiştiğinde kaydedilir.
    

Eğer çok yüksek hızda trafik varsa ve buffer küçükse paketler kaybolur. -B buffer büyüklüğünü artırarak bunu önler.
---

#### `-I` veya `--monitor-mode`
**Ne İşe Yarar:** Monitor mode'u aktifleştirir (WiFi için, sadece bazı interface'lerde çalışır).

**Ne Zaman Kullanılır:**
- WiFi trafiğini yakalamak için (diğer AP'lerin trafiği dahil)

**Örnek:**
```bash
tcpdump -i wlan0 -I
```

**Not:** Monitor mode için interface'in desteklemesi gerekir. `iwconfig wlan0 mode monitor` ile aktif edilebilir.

---

#### `-j <stamp_type>` veya `--time-stamp-type=<stamp_type>`
**Ne İşe Yarar:** Timestamp tipini belirler.

**Ne Zaman Kullanılır:**
- Farklı timestamp formatları için

**Örnek:**
```bash
tcpdump -i eth0 -j host
```

---

#### `-J` veya `--list-time-stamp-types`
**Ne İşe Yarar:** Desteklenen timestamp tiplerini listeler.

**Ne Zaman Kullanılır:**
- Hangi timestamp tiplerinin mevcut olduğunu görmek için

**Örnek:**
```bash
tcpdump -J
```

# 🔹 **tcpdump `-j` ve `-J` farkı**

## ✅ **1) `-j` → Timestamp formatı seçer**

`-j` seçeneği, tcpdump’ın **paket zaman damgasını HANGİ kaynak saatten alacağını** belirler.

Kullanım örneği:

`tcpdump -j host tcpdump -j adapter_unsynced tcpdump -j adapter tcpdump -j bluetooth`

Kısaca:

- **host** → İşletim sisteminin saatini kullan
    
- **adapter** → NIC’in kendi saatini kullan
    
- **adapter_unsynced** → NIC saati ama senkronize olmayabilir
    
- **bluetooth** → Bluetooth timestamp kaynakları
    

### 🔍 Ne işe yarar?

Forensics/paket inceleme yaparken doğru zaman kaynağını seçmek gerekir.  
Özellikle:

- Donanım timestamp’i istiyorsan → adapter
    
- Normal OS timestamp yeterliyse → host
    

---

## ✅ **2) `-J` → Desteklenen timestamp listelerini gösterir**

Kısaca:

`tcpdump -J`

→ Sisteminin ve NIC’inin desteklediği tüm timestamp modlarını listeler.

### Örnek çıktı:

`host adapter adapter_unsynced bluetooth`

Bu sayede `-j` ile neleri seçebileceğini öğrenirsin.

---

# 🔹 Özet Tablo

| Seçenek | Ne Yapıyor?                                   |
| ------- | --------------------------------------------- |
| **-j**  | Hangi timestamp kaynağını kullanacağını seçer |
| **-J**  | Desteklenen timestamp kaynaklarını listeler   |
## 🎯 5. BPF (Berkeley Packet Filter) Filtreleme

tcpdump, **BPF syntax** kullanarak trafiği filtreler. Bu çok güçlü bir filtreleme sistemidir.

### 5.1. Temel BPF Filtreleri

#### Port Filtreleme
```bash
# Port 80 (HTTP)
tcpdump -i eth0 port 80

# Port 443 (HTTPS)
tcpdump -i eth0 port 443

# Port 80 veya 443
tcpdump -i eth0 port 80 or port 443

# Port 80 değil
tcpdump -i eth0 not port 80

# Port aralığı (1-1024)
tcpdump -i eth0 portrange 1-1024
```

#### IP Adresi Filtreleme
```bash
# Belirli bir IP'den gelen
tcpdump -i eth0 src host 192.168.1.10

# Belirli bir IP'ye giden
tcpdump -i eth0 dst host 192.168.1.10

# Belirli bir IP (her iki yön)
tcpdump -i eth0 host 192.168.1.10

# Network (subnet)
tcpdump -i eth0 net 192.168.1.0/24
```

#### Protokol Filtreleme
```bash
# Sadece TCP
tcpdump -i eth0 tcp

# Sadece UDP
tcpdump -i eth0 udp

# Sadece ICMP
tcpdump -i eth0 icmp

# Sadece ARP
tcpdump -i eth0 arp
```

#### Kombinasyonlar
```bash
# TCP ve port 80
tcpdump -i eth0 tcp port 80

# 192.168.1.10'dan 8.8.8.8'e port 53 (DNS)
tcpdump -i eth0 src host 192.168.1.10 and dst host 8.8.8.8 and port 53

# HTTP veya HTTPS
tcpdump -i eth0 port 80 or port 443
```

### 5.2. İleri Seviye BPF Filtreleri

#### Paket Boyutu
```bash
# 100 byte'dan büyük paketler
tcpdump -i eth0 greater 100

# 64 byte'dan küçük paketler
tcpdump -i eth0 less 64
```

#### TCP Flag'leri
```bash
# SYN paketleri
tcpdump -i eth0 'tcp[tcpflags] & tcp-syn != 0'

# SYN-ACK paketleri
tcpdump -i eth0 'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack != 0'

# RST paketleri
tcpdump -i eth0 'tcp[tcpflags] & tcp-rst != 0'
```

#### Payload İçeriği
```bash
# "GET" string'ini içeren paketler
tcpdump -i eth0 -A 'tcp port 80 and tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420'

# Daha kolay yol (ASCII string)
tcpdump -i eth0 -A -s 0 'tcp port 80 and tcp contains "GET"'
```

#### IP TTL
```bash
# TTL 64 olan paketler
tcpdump -i eth0 'ip[8] = 64'
```

---

## 🔥 6. Pratik Senaryolar ve Kombinasyonlar

### Senaryo 1: HTTP Trafiğini Yakala ve Dosyaya Kaydet
```bash
tcpdump -i eth0 -w http_traffic.pcap -s 0 port 80
```
**Açıklama:** eth0'tan gelen HTTP trafiğini tam paket boyutuyla (`-s 0`) yakala ve `http_traffic.pcap` dosyasına kaydet.

---

### Senaryo 2: Belirli Bir Host'un Tüm Trafiğini Göster
```bash
tcpdump -i eth0 -nn -v host 192.168.1.10
```
**Açıklama:** 192.168.1.10'un tüm trafiğini DNS çözümlemesi olmadan (`-nn`) ve detaylı (`-v`) göster.

---

### Senaryo 3: ICMP Paketlerini Detaylı Göster
```bash
tcpdump -i eth0 -vvv -X icmp
```
**Açıklama:** ICMP paketlerini maksimum detay (`-vvv`) ve HEX/ASCII formatında (`-X`) göster.

---

### Senaryo 4: PCAP Dosyasını Analiz Et ve HTTP İsteklerini Bul
```bash
tcpdump -r capture.pcap -A -s 0 'tcp port 80 and tcp contains "GET"'
```
**Açıklama:** PCAP dosyasını oku, HTTP GET isteklerini ASCII formatında göster.

---

### Senaryo 5: SSH Bağlantı Denemelerini Yakala
```bash
tcpdump -i eth0 -nn 'tcp port 22 and tcp[tcpflags] & tcp-syn != 0'
```
**Açıklama:** Port 22'ye (SSH) gelen SYN paketlerini yakala (bağlantı denemeleri).

---

### Senaryo 6: DNS Sorgularını Göster
```bash
tcpdump -i eth0 -nn -X port 53
```
**Açıklama:** DNS trafiğini (port 53) HEX/ASCII formatında göster.

---

### Senaryo 7: Büyük Paketleri Yakala (DDoS Benzeri)
```bash
tcpdump -i eth0 -nn 'ip[2:2] > 1500'
```
**Açıklama:** 1500 byte'dan büyük paketleri yakala (fragmentation veya büyük payload analizi için).

---

### Senaryo 8: Belirli Bir MAC Adresinden Gelen Trafik
```bash
tcpdump -i eth0 -e 'ether src 00:11:22:33:44:55'
```
**Açıklama:** Belirli bir MAC adresinden gelen trafiği yakala (Layer 2 filtreleme).

---

### Senaryo 9: Rotating PCAP Dosyaları (Her Saat Yeni Dosya)
```bash
tcpdump -i eth0 -w capture_%H%M%S.pcap -G 3600 -C 100
```
**Açıklama:** Her saat yeni dosya oluştur (`-G 3600`), her dosya maksimum 100 MB olsun (`-C 100`).

---

### Senaryo 10: Real-time HTTP İsteklerini Göster
```bash
tcpdump -i eth0 -A -s 0 -l 'tcp port 80 and tcp contains "GET"' | grep --line-buffered "GET"
```
**Açıklama:** HTTP GET isteklerini real-time göster, line-buffered kullan (`-l`).

---

## 🧪 7. Debug ve Troubleshooting

### 7.1. Interface Listesi
```bash
tcpdump -D
```

### 7.2. Filtre Testi (Paket Yakalamadan)
```bash
tcpdump -d port 80
```

### 7.3. Verbose Mod ile Detaylı Bilgi
```bash
tcpdump -i eth0 -vvv
```

### 7.4. Paket Sayısını Sınırla (Test İçin)
```bash
tcpdump -i eth0 -c 10
```

---

## 📊 8. tcpdump vs Wireshark

| Özellik | tcpdump | Wireshark |
|---------|---------|-----------|
| **Arayüz** | Komut satırı | GUI |
| **Kullanım** | Hızlı, script'lenebilir | Detaylı analiz |
| **Kaynak Kullanımı** | Düşük | Yüksek |
| **Remote Kullanım** | SSH üzerinden kolay | X11 forwarding gerekir |
| **Otomasyon** | Script'lerde kullanılabilir | Manuel analiz |

**Ne Zaman tcpdump:**
- Hızlı trafik yakalama
- Script'lerde otomasyon
- SSH üzerinden remote analiz
- PCAP dosyası oluşturma

**Ne Zaman Wireshark:**
- Detaylı paket analizi
- Protocol decode
- Grafik analiz
- İstatistiksel analiz

---

## 🧹 9. Performans İpuçları

1. **Filtreleme:** Mümkün olduğunca BPF filtreleri kullan (kernel seviyesinde filtreleme, daha hızlı).
2. **Snaplen:** Gereksiz yere `-s 0` kullanma, sadece ihtiyacın kadarını yakala.
3. **DNS Çözümleme:** Production'da `-n` veya `-nn` kullan (DNS lookup yavaşlatır).
4. **Buffer:** Yüksek trafikli ortamlarda `-B` ile buffer boyutunu artır.
5. **Dosya Rotation:** Uzun süreli yakalama için `-C` veya `-G` kullan.

---

## 🧱 10. Mini Lab Senaryosu

1. **Interface'i Listele:**
   ```bash
   tcpdump -D
   ```

2. **İlk 10 Paketi Yakala:**
   ```bash
   tcpdump -i eth0 -c 10 -nn
   ```

3. **HTTP Trafiğini Yakala ve Dosyaya Kaydet:**
   ```bash
   tcpdump -i eth0 -w http.pcap -s 0 port 80
   ```

4. **Başka Terminalden HTTP İsteği Yap:**
   ```bash
   curl http://example.com
   ```

5. **PCAP Dosyasını Analiz Et:**
   ```bash
   tcpdump -r http.pcap -A -s 0
   ```

6. **ICMP Paketlerini Detaylı Göster:**
   ```bash
   tcpdump -i eth0 -vvv -X icmp
   ```

7. **Ping At ve Sonuçları Gör:**
   ```bash
   # Terminal 1
   tcpdump -i eth0 -nn icmp
   
   # Terminal 2
   ping -c 4 8.8.8.8
   ```

---

## 📚 11. Devam Kaynakları

- **tcpdump man page:** `man tcpdump`
- **BPF Syntax:** Berkeley Packet Filter dokümantasyonu
- **Wireshark:** PCAP dosyalarını detaylı analiz için
- **TryHackMe:** Network analysis modülleri
- **pcap-ng format:** Modern PCAP formatı

---

## 🎓 12. Özet: En Çok Kullanılan Kombinasyonlar

### Temel Yakalama
```bash
tcpdump -i eth0 -nn
```

### HTTP Trafiği
```bash
tcpdump -i eth0 -A -s 0 port 80
```

### PCAP Kaydetme
```bash
tcpdump -i eth0 -w capture.pcap -s 0
```

### PCAP Okuma
```bash
tcpdump -r capture.pcap -nn -A
```

### Detaylı Analiz
```bash
tcpdump -i eth0 -vvv -X -s 0
```

### Belirli Host
```bash
tcpdump -i eth0 -nn host 192.168.1.10
```

### Port Filtreleme
```bash
tcpdump -i eth0 -nn port 80 or port 443
```

### ICMP Analizi
```bash
tcpdump -i eth0 -vvv -X icmp
```

Bu dokümanı referans olarak kullanarak tcpdump'ın tüm flag'lerini ve kullanım senaryolarını öğrenebilirsin. Pratik yaparak daha da iyi öğrenirsin! 🚀

