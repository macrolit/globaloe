# Obsidian Global-Markdown-Encrypt

**Feature Overhaul Update**

## Features

- **Ephemeral In-Memory Decryption:**  
    Decrypts selected markdown files (or the entire vault for small vaults) into RAM only. No decrypted data is ever written to disk.
    
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
  File extension notes are visible within Obsidian once the plugin is enabled and decrypted with the password.
  
- **Cloud environments**
	Can be securely used for safe storage of sensitive files in cloud services

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


## Caveats

- **Not necessarily Zero-Knowledge**
  Not Zero-Knowledge since the file structure is plainly exposed, so it's up to the user to manage file structures and discreet management.
  
- **Early Implementation**
  Expect some things to break and make sure to back up your files regularly, data loss may occur.

- **Multiple Files**
  Multi-tab usability may be limited.


### Bottom Line

This is an enhancement for a work-around project to note-wise encryption security in Obsidian, especially compatible for cloud environments. Although not being a zero-trace zero-knowledge approach, it is decent enough to keep oneself (relatively) calm when it comes to sending sensitive files to foreign cloud servers.



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
