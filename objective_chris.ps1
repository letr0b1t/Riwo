<#
Dieses PowerShell-Skript automatisiert die Erstellung einer OU-Struktur, konfiguriert einen Fileserver und erstellt Benutzerkonten sowie Freigaben für Abteilungsdaten.

Schritte zur Verwendung des Skripts:
1. Passe die Domain, den Servernamen und andere erforderliche Variablen entsprechend an.
2. Führe das Skript mit Administratorrechten aus.
3. Überprüfe die erstellte OU-Struktur, den Fileserver, die Benutzerkonten und die Freigaben.

Hinweise:
- Stelle sicher, dass die erforderlichen PowerShell-Module (z.B. Active Directory-Modul) installiert und importiert sind.
- Dieses Skript deckt grundlegende Konfigurationen ab und kann an spezifische Anforderungen angepasst werden.

Verfasser: [Dein Name]
Datum: [Aktuelles Datum]
#>

# OU-Struktur erstellen
$departments = @("Abteilung1", "Abteilung2", "Abteilung3", "Abteilung4", "Abteilung5")
$ouPath = "OU=Unternehmen,DC=domain,DC=com"  # Passe die Domain entsprechend an

foreach ($department in $departments) {
    $ouName = "OU=$department,$ouPath"
    New-ADOrganizationalUnit -Name $department -Path $ouPath -ErrorAction SilentlyContinue
}

# Fileserver-Konfiguration
$serverName = "SRV-2019-003"  # Passe den Servernamen an
$ipAddress = "192.168.0.10"  # Passe die IP-Adresse an

# Hier kannst du die grundlegende Konfiguration für den Fileserver durchführen, wie zum Beispiel IP-Einstellungen.
# Füge den entsprechenden Code ein, um die Konfiguration vorzunehmen.

# Benutzer erstellen und Homeverzeichnisse erstellen
$usersPerDepartment = 5

foreach ($department in $departments) {
    $departmentOU = "OU=$department,$ouPath"

    for ($i = 1; $i -le $usersPerDepartment; $i++) {
        $username = "User$department$i"
        $userOU = "OU=Mitarbeiter,$departmentOU"
        $homeDirectory = "\\$serverName\Home\$username"

        # Benutzer erstellen
        New-ADUser -Name $username -SamAccountName $username -UserPrincipalName "$username@domain.com" -Path $userOU -Enabled $true -PasswordNeverExpires $true -ChangePasswordAtLogon $false

        # Homeverzeichnis erstellen
        New-Item -Path $homeDirectory -ItemType Directory | Out-Null

        # Berechtigungen für den Benutzer auf dem Homeverzeichnis setzen
        $acl = Get-Acl -Path $homeDirectory
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($username, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $acl.SetAccessRule($rule)
        Set-Acl -Path $homeDirectory -AclObject $acl
    }
}

# Freigabe für "Techotrans-Daten" erstellen
$techotransDataPath = "\\$serverName\Techotrans-Daten"
New-Item -Path $techotransDataPath -ItemType Directory | Out-Null

# Berechtigungen für "Techotrans-Daten" setzen
$acl = Get-Acl -Path $techotransDataPath
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Domain Users", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.SetAccessRule($rule)
Set-Acl -Path $techotransDataPath -AclObject $acl

# Abteilungsordner und "Shared"-Ordner unterhalb von "Techotrans-Daten" erstellen
foreach ($department in $departments) {
    $departmentDataPath = Join-Path -Path $techotransDataPath -ChildPath $department
    New-Item -Hier ist die Fortsetzung des PowerShell-Skripts:

```powershell
Path $departmentDataPath -ItemType Directory | Out-Null

    # Berechtigungen für den Abteilungsordner setzen
    $acl = Get-Acl -Path $departmentDataPath
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Domain Users", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.SetAccessRule($rule)
    Set-Acl -Path $departmentDataPath -AclObject $acl
}

# "Shared"-Ordner unterhalb von "Techotrans-Daten" erstellen
$sharedDataPath = Join-Path -Path $techotransDataPath -ChildPath "Shared"
New-Item -Path $sharedDataPath -ItemType Directory | Out-Null

# Berechtigungen für den "Shared"-Ordner setzen
$acl = Get-Acl -Path $sharedDataPath
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Domain Users", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.SetAccessRule($rule)
Set-Acl -Path $sharedDataPath -AclObject $acl

# Netzlaufwerke für Benutzer konfigurieren
foreach ($department in $departments) {
    for ($i = 1; $i -le $usersPerDepartment; $i++) {
        $username = "User$department$i"
        $userHomeDrive = "H:"
        $userTechotransDrive = "T:"

        # Netzlaufwerk für Homeverzeichnis zuweisen
        $homeDrivePath = Join-Path -Path $serverName -ChildPath "Home\$username"
        New-PSDrive -Name $userHomeDrive -PSProvider FileSystem -Root $homeDrivePath -Persist

        # Netzlaufwerk für "Techotrans-Daten" zuweisen
        New-PSDrive -Name $userTechotransDrive -PSProvider FileSystem -Root $techotransDataPath -Persist
    }
}