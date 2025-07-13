# Obsidian Ephemeral Vault Encryption Plugin

**Secure, in-memory, zero-trace encryption for your Obsidian markdown vault.**

## Features

- **Ephemeral In-Memory Decryption:**  
    Decrypts selected markdown files (or the entire vault for small vaults) into RAM only. No decrypted data is ever written to disk.
    
- **Zero-Knowledge Encryption:**  
    All encryption and decryption is performed client-side. Only you hold the encryption key.
    
- **Secure Rendered Viewing:**  
    View decrypted notes in Obsidian’s reading (preview) mode without risk of unencrypted content being written to disk.
    
- **Read-Only Option:**  
    Optionally restrict decrypted files to read-only mode to prevent accidental unencrypted saves.
    
- **Multi-File In-Memory Support:**  
    Decrypt and view multiple markdown files simultaneously in memory (for multi-tab workflows).
    
- **Encrypted Filename Mapping:**  
    Filenames are encrypted on disk; the plugin maintains an in-memory mapping for displaying original filenames during use.
    
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
  
    - The file name is rendered from YAML frontmatter into the dedicated toolbar
        
2. **While Open:**
    
    - The file can be toggled (in toolbar) to display in read-only rendered (markdown preview) mode.
      
    - The file can be toggled back to edit mode
        
3. **On File Close or App Exit:**
    
	- Changes are encrypted automatically and securely saved back to disk.

	- Decrypted content is wiped from memory.
        
    - No decrypted data is ever written to disk.
        
3. **On Save:**
    
    - If editing is enabled, changes are encrypted and saved back to disk in encrypted form only.

## Security Model

- **Zero-Traces:**  
    Decrypted content exists only in RAM during use and is never written to disk or swap.
    
- **Zero-Knowledge:**  
    Not truly 100% zero knowledge, but close enough (third parties can still see file structure)
    
- **Ephemeral Use:**  
    All decrypted data is wiped from memory when not in use.
  
- **Cloud environments**
	Can be securely used for safe storage of sensitive files in cloud services

## Dedicated file explorer

- **Encrypted Index**
  File names are simply not present as in usual files and stored instead in YAML frontmatter and an encrypted index file (file explorer index)

- **When entering password**
  An index from encrypted file contents in the vault is decrypted at password enter event and utilised for a content view table with actual file names

## Usage

1. **Install the Plugin:**  
    Download and install from the Obsidian community plugins directory or manually from this repository.
    
2. **Set Your Encryption Password:**  
    The plugin will prompt you to set or enter your vault password.
    
3. **Open Encrypted Files:**  
    Click any encrypted file to decrypt and view it securely in memory.
    
4. **Work as Usual:**  
    View or (optionally) edit your notes. Use multi-tab for multiple files.
    
5. **Close Files or Exit:**  
    All decrypted content is wiped from memory automatically.










# global-markdown-encrypt

a plugin for encrypting obsidian markdowns in-memory, single password based.

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

## supported modes

due to technical reasons, only markdown with editing view is supported.

- please use editing view as default
- only markdown files with aes256 extensions are encrypted (excluding: images, etc.)

## disclaimer

risk of data loss, when there is an unexpected error. please backup your important data periodically.
