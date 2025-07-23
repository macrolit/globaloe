# Obsidian Global-Markdown-Encrypt

**Feature Overhaul Update**

## Features

- **Ephemeral In-Memory Decryption:**  
    Decrypts selected markdown files into RAM only. No decrypted data is ever written to disk.
    
- **Secure Rendered View:**  
    View decrypted notes in Obsidian’s reading (preview) mode without risk of unencrypted content being written to disk.
    
- **Encrypted Filename Mapping:**  
    Filenames are securely encrypted on note's metadata; using the frontmatter for displaying original filenames at the dedicated toolbar.

- **Encrypted Files Explorer**
  	The explorer has a ribbon button for sidebar preview of the encrypted files within the vault, the plugin maintains an in-memory mapping of encrypted index file for file names during use of the sidebar preview.
    
- **Automatic Memory Wipe:**  
    Decrypted content is securely wiped from RAM when files are closed or the app is exited.
    
- **Cloud Sync Safe:**  
    Only encrypted files are ever written to your cloud-synced folders, preventing accidental leaks.
    
- **Mobile-First Design:**  
    Optimized for mobile devices with careful RAM and lifecycle management.
    

## How It Works

1. **On File Open:**
    
    - The plugin decrypts the file in memory.
        
    - Allows for plain editing only in RAM memory.
  
    - The file name is rendered from YAML frontmatter into the dedicated toolbar plugin integration
        
2. **While Open:**
    
    - The file can be toggled (in toolbar) to display in read-only rendered (markdown preview) mode.
      
    - The file can be toggled back to edit mode
  
    - Regular Markdown files (.md) are rendered as default and the plugin does not interfere with it's regular workflow
        
3. **On File Close or App Exit:**
    
	- Changes are encrypted automatically and securely saved back to disk.

	- Decrypted content is wiped from memory.
        
    - No decrypted data is ever written to disk.

		
3. **On Save:**
    
    - If editing is enabled, changes are encrypted and saved back to disk in encrypted form only.


## Security Model
    
- **Ephemeral Use:**  

  All decrypted data is wiped from memory when not in use.

- **AES256 Encryption**

  Notes fully encrypted with AES-256-GCM. Using authenticated encryption, preventing tampering. Encrypted notes are visible within Obsidian once the plugin is enabled and decrypted with the password.
  
- **Cloud environments**

  Can be securely used for safe storage of sensitive files in cloud services

- **Isolated Usability**
  
  Community plugins, Core plugins, other Obsidian functionaly and basic editor features are isolated from .aes256 files within the vault.
  
- **Secure Filename Model**
  
  Custom filenames encrypted and stored separately from file metadata.

- **Secure Markdown Rendering**

  Document structure: Markdown formatting hidden within encrypted content.

- **Secure Salt Generation**
  
  Securely generated encryption salt as per-vault basis.

- **Secure Memory**
  
  The code uses typed arrays (Uint8Array) for handling sensitive data in secure buffers, which can be cleared from memory more effectively than strings. 

- **Safe Clearing**

  The SecureMemory.clearBuffer method ensures that sensitive data is cleared from memory by filling buffers with random values and then zeroing them out.

- **Strong Key Derivation**
  
  PBKDF2: 1,000,000 iterations provide strong key derivation, also using SHA-512 as strong hashing algorithm.
  
- **Random IV Derivation**
  
  Each encryption uses a fresh IV.

- **Timing Attack Protection**
  
  The SecureMemory.secureEquals method provides a secure way to compare sensitive data, protecting against timing attacks.

## **Security Viability**

Strong against: Brute force attacks (due to 1M PBKDF2 iterations)
Moderate against: Most cryptographic attacks (solid AES-256-GCM)


## Dedicated file explorer

- **Encrypted Index**

  File names are simply not present as in usual files and stored instead in YAML frontmatter and written to an encrypted index file (file explorer index)

- **When entering password**

  An index from encrypted file contents in the vault is decrypted at password enter event and utilised for a content view table with actual file names

## Usage

1. **Install the Plugin:**  
    Download and install from the Obsidian community plugins directory or manually from this repository.
    
2. **Set Your Encryption Password:**  
    The plugin will prompt you to enter your vault password. (the longer the more secure)
    
3. **Open Encrypted Files:**  
    Click any encrypted file to decrypt and view it securely in memory.
    
4. **Work as Usual:**  
    View or edit your notes by using the change-mode toggle switch.
    
5. **Close Files or Exit:**  
    All decrypted content is wiped from memory automatically.




## **Information Leakage**

While file content is fully encrypted, an observer can see:

- Which files are encrypted (.aes256 extension): Number of encrypted files
- File sizes (±16 bytes): Approximate content length discernible
- Access patterns: Frequency of file access observable
- Directory names and folder structure: Everything other than .aes256 notes is handled by Obsidian in plain text
- File timestamps: Creation/modification times visible
- Limitations of JavaScript: It's important to note that JavaScript has some limitations when it comes to memory security. For example, strings are immutable and cannot be cleared from memory directly. The code minimizes the use of strings for sensitive data and converts them to secure buffers as soon as possible.


## Caveats

- **Not necessarily Zero-Knowledge**

  Not Zero-Knowledge compatible since the file structure is plainly exposed, as well as significant metadata leakage (file sizes, timestamps, counts) so it's up to the user to manage file structures and metadata for discreet information management.
  
- **Early Implementation**

  Expect some things to break and make sure to back up your files regularly, data loss may occur.

- **Limited Multiple File Editing**

  Multi-tab usability may be limited.

- **Limited Interaction**
  
  Other plugins cannot interact with the encrypted notes for security reasons.


### Bottom Line

This is an enhancement for a work-around project to note-wise encryption security in Obsidian, especially compatible for cloud environments. Although not being a zero-trace zero-knowledge approach, it is decent enough to keep oneself (relatively) calm when it comes to syncing sensitive files to foreign cloud servers.

##### Suitability:
✅ Good for: Personal notes, casual privacy protection, cloud storage protection

❌ Not suitable for: Enterprise use, highly sensitive data, passcode or key storage, compliance requirements

##### Possible Improvements:

- Short-term: 
Add password strength requirements

- Long-term: 
Consider implementing metadata-proof measures (file size obfuscation, timestamp randomization, etc.)

- If Possible: 
Prevent Side-Channel Vulnerabilities (Medium Risk); 
~~Timing attacks: Password verification timing could leak some information~~ (done), 
Memory access patterns: Could be analyzed in sophisticated attacks


## Update Notice: 
### The Update auto-detects and upgrades salts from the old legacy salt to a safely generated one. 
### ⚠️ **Users that had a custom salt MUST decrypt and manually transfer their files before updating the plugin in order to avoid DATA CORRUPTION**


# Default Plugin Specs

A plugin for encrypting obsidian markdowns in-memory, single password based.

## how to use

please follow these steps.

- set editing view as default (Settings / Editor / Default view for new tabs -> Editing view)
- turn on the plugin
- input your password (the longer, the stronger)
- click 'note with lock' icon
- the markdown with 'aes256' extensions are seamlessly encrypted

## spec

cryptographic algorithms were chosen conservately.

- key derivation: pbkdf2-sha512 with 1000000 iters
- mode of operation: aes256-gcm aead (auth + encryption)
- file extension: aes256


## disclaimer

risk of data loss, when there is an unexpected error. please backup your important data periodically.
