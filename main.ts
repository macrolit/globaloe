import { 
    App, 
    Editor, 
    Modal, 
    Plugin, 
    Menu, 
    PluginSettingTab, 
    Setting,
    normalizePath, 
    Notice, 
    TFolder, 
    moment, 
    MarkdownRenderer, 
    Component, 
    TFile, 
    parseFrontMatterEntry, 
    parseYaml, 
    stringifyYaml,
    ViewState, 
    MarkdownView, 
    TextFileView, 
    WorkspaceLeaf, 
    View 
} from 'obsidian';

const subtle = crypto.subtle;
const JsCrypto = require('jscrypto');

const b64tou8 = (x: string) => Uint8Array.from(atob(x), c => c.charCodeAt(0));

async function pbkdf2Async(password: string, salt: string, iterations: number) {
    const ec = new TextEncoder();
    
    // Use secure buffer for password
    const passwordBuffer = SecureMemory.stringToSecureBuffer(password);
    
    try {
        const keyMaterial = await subtle.importKey('raw', passwordBuffer, 'PBKDF2', false, ['deriveKey']);
        const key = await subtle.deriveKey(
            { 
                name: 'PBKDF2', 
                hash: 'SHA-512', 
                salt: ec.encode(salt), 
                iterations: iterations 
            }, 
            keyMaterial, 
            { 
                name: 'AES-GCM', 
                length: 256 
            }, 
            true, 
            ['encrypt', 'decrypt']
        );
        
        const exported = new JsCrypto.Word32Array(new Uint8Array(await subtle.exportKey("raw", key)));
        return exported;
    } finally {
        // Always clear the password buffer
        SecureMemory.clearBuffer(passwordBuffer);
    }
}


const aes256gcm = (key: any) => {
  const encrypt = (msg: any, origIv: any) => {
    let iv = crypto.getRandomValues(new Uint8Array(12));
    if(origIv)
        iv = b64tou8(origIv);

    iv = new JsCrypto.Word32Array(iv);
    msg = JsCrypto.Utf8.parse(msg);

    let encryptedData = JsCrypto.AES.encrypt(msg, key, {iv: iv, mode: JsCrypto.mode.GCM});
    let ciphertext = encryptedData.cipherText;
    let authTag = JsCrypto.mode.GCM.mac(JsCrypto.AES, key, iv, JsCrypto.Word32Array([]), ciphertext, 16);
    let encryptedPayload = encryptedData.toString();

    return [encryptedPayload, JsCrypto.Base64.stringify(iv), JsCrypto.Base64.stringify(authTag)];
  };

  const decrypt = (encryptedPayload: any, iv: any, authTag: any) => {
    iv = JsCrypto.Base64.parse(iv);
    let decryptedData = JsCrypto.AES.decrypt(encryptedPayload, key, {iv: iv, mode: JsCrypto.mode.GCM});

    let ciphertext = JsCrypto.formatter.OpenSSLFormatter.parse(encryptedPayload).cipherText;
    if(authTag !== JsCrypto.Base64.stringify(JsCrypto.mode.GCM.mac(JsCrypto.AES, key, iv, JsCrypto.Word32Array([]), ciphertext))) {
        throw new Error('authentication fail');
    }

    return JsCrypto.Utf8.stringify(decryptedData);
  };

  return {
    encrypt,
    decrypt,
  };
};


export const VIEW_TYPE_ENCRYPTED_FILE = "encrypted-file-view";
export const VIEW_TYPE_ENCRYPTED_PREVIEW = "encrypted-preview-view";
export const VIEW_TYPE_ENCRYPTED_EXPLORER = "encrypted-explorer-view";
export const DEFAULT_SALT_VALUE = ""; // Will be generated per-vault

// Utility functions for YAML parsing
function extractFrontMatter(content: string): { frontMatter: any; body: string } {
    const frontMatterRegex = /^---\n([\s\S]*?)\n---\n([\s\S]*)$/;
    const match = content.match(frontMatterRegex);
    
    if (match) {
        try {
            const frontMatter = parseYaml(match[1]);
            return { frontMatter, body: match[2] };
        } catch (e) {
            console.warn('Failed to parse YAML front matter:', e);
            return { frontMatter: {}, body: content };
        }
    }
    
    return { frontMatter: {}, body: content };
}

function addOrUpdateFrontMatter(content: string, updates: any): string {
    const { frontMatter, body } = extractFrontMatter(content);
    const newFrontMatter = { ...frontMatter, ...updates };
    
    const yamlString = stringifyYaml(newFrontMatter);
    return `---\n${yamlString}---\n${body}`;
}



// Secure memory utilities for handling sensitive data
class SecureMemory {
    static createSecureBuffer(size: number): Uint8Array {
        return new Uint8Array(size);
    }

    static clearBuffer(buffer: Uint8Array): void {
        if (buffer && buffer.length > 0) {
            crypto.getRandomValues(buffer);
            buffer.fill(0);
        }
    }

    static stringToSecureBuffer(str: string): Uint8Array {
        const encoder = new TextEncoder();
        return encoder.encode(str);
    }

    static secureBufferToString(buffer: Uint8Array): string {
        const decoder = new TextDecoder();
        return decoder.decode(buffer);
    }

    // Secure string comparison using typed arrays to prevent timing attacks
    static secureEquals(a: Uint8Array, b: Uint8Array): boolean {
        if (a.length !== b.length) return false;
        
        let result = 0;
        for (let i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result === 0;
    }
}

// Salt generation and management
class SaltManager {
    private static readonly SALT_KEY = 'vault_encryption_salt';
    private static readonly SALT_LENGTH = 32; // 256 bits

    static generateSalt(): string {
        const saltBytes = new Uint8Array(this.SALT_LENGTH);
        crypto.getRandomValues(saltBytes);
        return Array.from(saltBytes, byte => byte.toString(16).padStart(2, '0')).join('');
    }

    static async getVaultSalt(plugin: GlobalMarkdownEncrypt): Promise<string> {
        try {
            const data = await plugin.loadData();
            
            if (data && data[this.SALT_KEY] && typeof data[this.SALT_KEY] === 'string' && data[this.SALT_KEY].length === this.SALT_LENGTH * 2) {
                return data[this.SALT_KEY];
            }

            const newSalt = this.generateSalt();
            
            const currentData = data || {};
            currentData[this.SALT_KEY] = newSalt;
            await plugin.saveData(currentData);
            
            return newSalt;
        } catch (error) {
            console.error('Failed to manage vault salt:', error);
            return this.generateSalt();
        }
    }

    static async migrateSalt(plugin: GlobalMarkdownEncrypt, oldSalt: string): Promise<string> {
        const newSalt = await this.getVaultSalt(plugin);
        
        // Skip if already migrated or same salt
        if (newSalt === oldSalt) return newSalt;
    
        // Only migrate from hardcoded salt
        if (oldSalt === "7f2ea27bd475702540c5211aed17904202a3ac06b0e87fdd8fcdec960a0fe388") {
            new Notice('Migrating encrypted files to new security standard...', 10000);
            
            // 1. Get current password
            const currentPassword = plugin.getPasswordManager().getPassword();
            if (!currentPassword) {
                new Notice('Password required for migration', 5000);
                return newSalt;
            }
            
            // 2. Create cipher with old salt
            const oldKey = await pbkdf2Async(currentPassword, oldSalt, 1000000);
            const oldCipher = aes256gcm(oldKey);
            
            // 3. Create cipher with new salt
            const newKey = await pbkdf2Async(currentPassword, newSalt, 1000000);
            const newCipher = aes256gcm(newKey);
            
            // 4. Get all encrypted files
            const encryptedFiles = plugin.app.vault.getFiles().filter(f => f.extension === 'aes256');
            let successCount = 0;
            
            console.log(`Found ${encryptedFiles.length} encrypted files to migrate`);
            
            // 5. Migrate each file
            for (const file of encryptedFiles) {
                try {
                    console.log(`Migrating ${file.path}...`);
                    const content = await plugin.app.vault.read(file);
                    const encryptedData = JSON.parse(content);
                    
                    // Check if this file needs migration (has old salt or no salt field)
                    if (encryptedData.salt && encryptedData.salt === newSalt) {
                        console.log(`${file.path} already migrated`);
                        successCount++;
                        continue;
                    }
                    
                    // Decrypt with OLD salt/cipher
                    const decrypted = oldCipher.decrypt(
                        encryptedData.ciphertext,
                        encryptedData.iv,
                        encryptedData.tag
                    );
                    
                    console.log(`Successfully decrypted ${file.path}`);
                    
                    // Re-encrypt with NEW salt and NEW IV (don't pass old IV)
					const [newCiphertext, newIv, newTag] = newCipher.encrypt(decrypted, null);
					                                                        
                    // Save with new encryption
                    const newEncryptedData = {
                        iv: newIv,
                        tag: newTag,
                        ciphertext: newCiphertext,
                        salt: newSalt
                    };
                    
                    await plugin.app.vault.modify(file, JSON.stringify(newEncryptedData, null, 2));
                    
                    console.log(`Successfully migrated ${file.path}`);
                    successCount++;
                    
                } catch (e) {
                    console.error(`Failed to migrate ${file.path}:`, e);
                    new Notice(`Failed to migrate ${file.name} - ${e.message}`, 5000);
                }
            }
            
            new Notice(`Migration complete! ${successCount}/${encryptedFiles.length} files migrated.`, 8000);
            
            if (successCount < encryptedFiles.length) {
                new Notice(`${encryptedFiles.length - successCount} files failed to migrate. Check console for details.`, 10000);
            }
        }
        
        return newSalt;
    }
}

// Enhanced password handling with secure memory management
class SecurePasswordManager {
    private passwordBuffer: Uint8Array | null = null;
    private static instance: SecurePasswordManager | null = null;

    private constructor() {}

    static getInstance(): SecurePasswordManager {
        if (!this.instance) {
            this.instance = new SecurePasswordManager();
        }
        return this.instance;
    }

    setPassword(password: string): void {
        this.clearPassword();
        this.passwordBuffer = SecureMemory.stringToSecureBuffer(password);
    }

    getPassword(): string | null {
        if (!this.passwordBuffer) return null;
        return SecureMemory.secureBufferToString(this.passwordBuffer);
    }

    clearPassword(): void {
        if (this.passwordBuffer) {
            SecureMemory.clearBuffer(this.passwordBuffer);
            this.passwordBuffer = null;
        }
    }

    hasPassword(): boolean {
        return this.passwordBuffer !== null && this.passwordBuffer.length > 0;
    }
}

// Custom encrypted file explorer view
export class EncryptedExplorerView extends View {
    plugin: GlobalMarkdownEncrypt;
    
    constructor(leaf: WorkspaceLeaf, plugin: GlobalMarkdownEncrypt) {
        super(leaf);
        this.plugin = plugin;
    }

    getViewType(): string {
        return VIEW_TYPE_ENCRYPTED_EXPLORER;
    }

    getDisplayText(): string {
        return "Encrypted Files";
    }

    getIcon(): string {
        return "file-lock";
    }

    async onOpen(): Promise<void> {
        this.containerEl.empty();
        this.containerEl.addClass('encrypted-explorer-view');
        
        await this.refresh();
    }

    async refresh(): Promise<void> {
        this.containerEl.empty();
        
        const headerEl = this.containerEl.createEl('div', { cls: 'encrypted-explorer-header' });
        headerEl.createEl('h4', { text: '🔒 Encrypted Files' });
        
        const refreshBtn = headerEl.createEl('button', { text: 'Refresh', cls: 'clickable-icon' });
        refreshBtn.onclick = () => this.refresh();
        
        const filesContainer = this.containerEl.createEl('div', { cls: 'encrypted-files-container' });
        
        // Get all .aes256 files
        const encryptedFiles = this.app.vault.getFiles().filter(file => file.extension === 'aes256');
        
        if (encryptedFiles.length === 0) {
            filesContainer.createEl('div', { text: 'No encrypted files found', cls: 'encrypted-no-files' });
            return;
        }
        
        for (const file of encryptedFiles) {
            const fileEl = filesContainer.createEl('div', { cls: 'encrypted-file-item' });
            
            // Get display name from index
            const displayName = await this.plugin.getDisplayName(file.path);
            
            const nameEl = fileEl.createEl('div', { 
                text: displayName, 
                cls: 'encrypted-file-name clickable-icon' 
            });
            
            const pathEl = fileEl.createEl('div', { 
                text: file.path, 
                cls: 'encrypted-file-path' 
            });
            
            // Add click handlers
            nameEl.onclick = () => {
                const leaf = this.app.workspace.getLeaf(false);
                if (this.plugin.settings.defaultViewMode === 'edit') {
                    leaf.setViewState({
                        type: VIEW_TYPE_ENCRYPTED_FILE,
                        state: { file: file.path, mode: 'source' }
                    });
                } else {
                    leaf.setViewState({
                        type: VIEW_TYPE_ENCRYPTED_PREVIEW,
                        state: { file: file.path }
                    });
                }
            };
            
            // Add context menu
            fileEl.oncontextmenu = (e) => {
                e.preventDefault();
                const menu = new Menu();
                
                menu.addItem(item => {
                    item.setTitle('Open in Preview Mode')
                        .setIcon('eye')
                        .onClick(() => {
                            const leaf = this.app.workspace.getLeaf(false);
                            leaf.setViewState({
                                type: VIEW_TYPE_ENCRYPTED_PREVIEW,
                                state: { file: file.path }
                            });
                        });
                });
                
                menu.addItem(item => {
                    item.setTitle('Open in Edit Mode')
                        .setIcon('edit')
                        .onClick(() => {
                            const leaf = this.app.workspace.getLeaf(false);
                            leaf.setViewState({
                                type: VIEW_TYPE_ENCRYPTED_FILE,
                                state: { file: file.path, mode: 'source' }
                            });
                        });
                });
                
                menu.showAtMouseEvent(e);
            };
        }
        
        // Style the explorer
        this.addExplorerStyles();
    }
    
    private addExplorerStyles(): void {
        const style = document.createElement('style');
        style.textContent = `
            .encrypted-explorer-view {
                padding: 10px;
            }
            .encrypted-explorer-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 15px;
                padding-bottom: 8px;
                border-bottom: 1px solid var(--background-modifier-border);
            }
            .encrypted-files-container {
                display: flex;
                flex-direction: column;
                gap: 8px;
            }
            .encrypted-file-item {
                padding: 8px;
                border: 1px solid var(--background-modifier-border);
                border-radius: 4px;
                cursor: pointer;
            }
            .encrypted-file-item:hover {
                background-color: var(--background-modifier-hover);
            }
            .encrypted-file-name {
                font-weight: bold;
                margin-bottom: 4px;
            }
            .encrypted-file-path {
                font-size: 0.9em;
                color: var(--text-muted);
            }
            .encrypted-no-files {
                text-align: center;
                color: var(--text-muted);
                padding: 20px;
            }
        `;
        
        if (!document.head.querySelector('#encrypted-explorer-styles')) {
            style.id = 'encrypted-explorer-styles';
            document.head.appendChild(style);
        }
    }

    async onClose(): Promise<void> {
        // Clean up
    }
}

// Enhanced encrypted preview view with filename support
export class EncryptedPreviewView extends TextFileView {
    private encData: string = "";
    private aesCipher: any = null;
    private decryptedContent: string = "";
    private contentComponent: Component = new Component();
    private plugin: GlobalMarkdownEncrypt;
    private customFileName: string = "";
    
    constructor(leaf: WorkspaceLeaf, aesCipher: any, plugin: GlobalMarkdownEncrypt) {
        super(leaf);
        this.aesCipher = aesCipher;
        this.plugin = plugin;
    }

    canAcceptExtension(extension: string): boolean {
        return extension == 'aes256';
    }

    getViewType() {
        return VIEW_TYPE_ENCRYPTED_PREVIEW;
    }

    getDisplayText(): string {
        if (this.customFileName) {
            return `${this.customFileName} (Preview)`;
        }
        return this.file ? `${this.file.basename} (Preview)` : "Encrypted Preview";
    }

    async setViewData(data: string, clear: boolean): Promise<void> {
        this.encData = data;
        
        if (!clear) {
            new Notice('unsupported: 1 file with multiple tabs');
            return;
        }

        try {
            let encryptedData = JSON.parse(data);
            this.decryptedContent = this.aesCipher.decrypt(encryptedData.ciphertext, encryptedData.iv, encryptedData.tag);
            
            // Extract filename from YAML front matter
            const { frontMatter } = extractFrontMatter(this.decryptedContent);
            if (frontMatter.filename) {
                this.customFileName = frontMatter.filename;
                // Update the index with the filename
                await this.plugin.updateFilenameIndex(this.file?.path || "", this.customFileName);
            }
            
            await this.renderMarkdown();
        } catch(e) {
            this.contentEl.empty();
            this.contentEl.createEl("div", { 
                text: "Decryption failed: invalid password or corrupted file",
                cls: "encrypted-error"
            });
        }
    }

    private async renderMarkdown(): Promise<void> {
        this.contentEl.empty();
        
        // Create toolbar with filename and switch button
        const toolbar = this.contentEl.createDiv({ cls: "encrypted-toolbar" });
        
        if (this.customFileName) {
            const filenameEl = toolbar.createEl("div", { 
                text: this.customFileName,
                cls: "encrypted-filename-display"
            });
            filenameEl.style.fontWeight = "bold";
            filenameEl.style.fontSize = "1.5em";
            filenameEl.style.marginBottom = "8px";
        }
        
        const switchContainer = toolbar.createDiv({ cls: "encrypted-switch-container" });
        switchContainer.style.display = "flex";
        switchContainer.style.alignItems = "center";
        switchContainer.style.gap = "8px";
        
        const switchLabel = switchContainer.createEl("span", { text: "✏️  Switch to Edit Mode" });

        const switchToggle = switchContainer.createEl("div", { cls: "checkbox-container" });
        switchToggle.innerHTML = '<input type="checkbox"><span class="checkmark"></span>';
        
        switchToggle.onclick = () => {
            this.plugin.switchEncryptedViewMode();
        };
        
        
        
        // Style the toolbar
        toolbar.style.padding = "10px";
        toolbar.style.borderBottom = "1px solid var(--background-modifier-border)";
        toolbar.style.backgroundColor = "var(--background-secondary)";
        
        
        // Create a container for the rendered markdown
        const previewContainer = this.contentEl.createDiv({ cls: "markdown-preview-view" });
        const previewContent = previewContainer.createDiv({ cls: "markdown-preview-sizer" });
        const previewSection = previewContent.createDiv({ cls: "markdown-preview-section" });
        
        // Render the decrypted markdown content (without front matter)
        const { body } = extractFrontMatter(this.decryptedContent);
        await MarkdownRenderer.render(
            this.app, 
            body, 
            previewSection, 
            this.file?.path || "", 
            this.contentComponent
        );
        
        // Add a header to indicate this is an encrypted file in preview mode
        const header = previewContainer.createDiv({ cls: "encrypted-preview-header" });
        header.createEl("small", { 
            text: "🔒 Encrypted file - Preview mode (read-only)",
            cls: "encrypted-preview-notice"
        });
        
        // Add styles for better presentation
        previewContainer.style.padding = "20px";
        header.style.textAlign = "center";
        header.style.marginBottom = "20px";
        header.style.opacity = "0.7";
        header.style.fontStyle = "italic";
    }

    getViewData(): string {
        // Always return the original encrypted data - never save decrypted content
        return this.encData;
    }

    clear(): void {
        this.decryptedContent = "";
        this.customFileName = "";
        this.contentComponent.unload();
        this.contentComponent = new Component();
    }

    onunload(): void {
        this.decryptedContent = "";
        this.customFileName = "";
        this.contentComponent.unload();
        super.onunload();
    }
}

// Enhanced encrypted file view with filename support
export class EncryptedFileView extends MarkdownView {
    private encData: string = "";
    private shouldUpdate: boolean = false;
    private aesCipher: any = null;
    private origIv: any = "";
    private saltValueToStoreWith: string = "";
    private plugin: GlobalMarkdownEncrypt;
    private customFileName: string = "";
    private lastContent: string = "";
    
    constructor(leaf: WorkspaceLeaf, aesCipher: any, saltValueToStoreWith: string, plugin: GlobalMarkdownEncrypt) {
        let origSetViewState = leaf.setViewState;
        leaf.setViewState = function(viewState: ViewState, eState?: any): Promise<void> {
            if(viewState.type !== VIEW_TYPE_ENCRYPTED_FILE || (viewState.state.mode && viewState.state.mode !== 'source') || (viewState.state.source && viewState.state.source !== false)) {
                this.detach();
                new Notice('unsupported: reading or unencrypted mode');
                return new Promise((resolve) => { setTimeout(resolve, 0); });
            } else {
                return origSetViewState.apply(this, [viewState, eState]);
            }
        };

        super(leaf);

        this.aesCipher = aesCipher;
        this.saltValueToStoreWith = saltValueToStoreWith;
        this.plugin = plugin;
    }

    // Monitor content changes to update filename index
    onInternalDataChange(): void {
        if (this.shouldUpdate) {
            const currentContent = this.editor.getValue();
            if (currentContent !== this.lastContent) {
                this.lastContent = currentContent;
                this.checkForFilenameChanges(currentContent);
            }
        }
    }

    private async checkForFilenameChanges(content: string): Promise<void> {
        const { frontMatter } = extractFrontMatter(content);
        const newFilename = frontMatter.filename || "";
        
        if (newFilename !== this.customFileName) {
            this.customFileName = newFilename;
            if (this.file) {
                await this.plugin.updateFilenameIndex(this.file.path, newFilename);
                // Update the view title
                const headerTitle = this.leaf.view.containerEl.querySelector('.view-header-title');
                if (headerTitle) {
                    headerTitle.textContent = this.getDisplayText();
                }
            }
        }
    }

    canAcceptExtension(extension: string): boolean {
        return extension == 'aes256';
    }

    getViewType() {
        return VIEW_TYPE_ENCRYPTED_FILE;
    }

    getDisplayText(): string {
        if (this.customFileName) {
            return `${this.customFileName} (Edit)`;
        }
        return this.file ? `${this.file.basename} (Edit)` : "Encrypted File";
    }

    setViewData(data: string, clear: boolean): void {
        this.encData = data;

        if(this.getState().mode != 'source') {
            this.shouldUpdate = false;
            this.leaf.detach();
            new Notice('unsupported: reading mode');
            return;
        }

        if(!clear) {
            this.shouldUpdate = false;
            this.leaf.detach();
            new Notice('unsupported: 1 file with multiple tabs');
            return;
        }

        try {
            let encryptedData = JSON.parse(data);
            const plaintext = this.aesCipher.decrypt(encryptedData.ciphertext, encryptedData.iv, encryptedData.tag);
            this.origIv = encryptedData.iv;
            this.lastContent = plaintext;

            // Extract filename from YAML front matter
            const { frontMatter } = extractFrontMatter(plaintext);
            if (frontMatter.filename) {
                this.customFileName = frontMatter.filename;
                // Update the index with the filename
                this.plugin.updateFilenameIndex(this.file?.path || "", this.customFileName);
            }

            this.editor.setValue(plaintext);
            this.shouldUpdate = true;
            
            // Add switch button and filename display to edit mode
            this.addSwitchButton();
        } catch(e) {
            this.shouldUpdate = false;
            this.leaf.detach();
            new Notice('decryption failed: invalid password');
        }
    }

    private addSwitchButton(): void {
        // Remove excess additional ribbon plugin buttons if any (FEEDBACK: Not working)
        const existingButton = this.contentEl.querySelector('.encrypted-edit-switch-button');
        if (existingButton) {
            existingButton.remove();
        }

        // Find the editor container
        const editorContainer = this.contentEl.querySelector('.cm-editor');
        if (editorContainer && editorContainer.parentElement) {
            // Create toolbar above editor
            const toolbar = editorContainer.parentElement.createDiv({ cls: "encrypted-edit-toolbar" });
            
            if (this.customFileName) {
                const filenameEl = toolbar.createEl("div", { 
                    text: this.customFileName,
                    cls: "encrypted-filename-display"
                });
                filenameEl.style.fontWeight = "bold";
                filenameEl.style.fontSize = "1.5em";
                filenameEl.style.marginBottom = "8px";
            }
            
            const switchContainer = toolbar.createDiv({ cls: "encrypted-switch-container" });
            switchContainer.style.display = "flex";
            switchContainer.style.alignItems = "center";
            switchContainer.style.gap = "8px";
            
            const switchLabel = switchContainer.createEl("span", { text: "👁️  Switch to Preview Mode" });

            const switchToggle = switchContainer.createEl("div", { cls: "checkbox-container" });
            switchToggle.innerHTML = '<input type="checkbox"><span class="checkmark"></span>';
            
            switchToggle.onclick = () => {
                this.plugin.switchEncryptedViewMode();
            };
            
            // Style the toolbar
            toolbar.style.padding = "10px";
            toolbar.style.borderBottom = "1px solid var(--background-modifier-border)";
            toolbar.style.backgroundColor = "var(--background-secondary)";
            
            
            // Insert toolbar before editor
            editorContainer.parentElement.insertBefore(toolbar, editorContainer);
        }
    }

    getViewData(): string {
        if(this.shouldUpdate) {
            try {
                if(this.aesCipher) {
                    let [ciphertext, iv, tag] = this.aesCipher.encrypt(this.editor.getValue(), this.origIv);
                    
                    const encData = JSON.stringify({
                        iv: iv,
                        tag: tag,
                        ciphertext: ciphertext,
                        salt: this.saltValueToStoreWith,
                    });

                    return encData;
                }
            } catch(e){
                console.error(e);
                new Notice(e, 10000);
            }
        }

        return this.encData;
    }
}


interface GlobalMarkdownEncryptSettings {
    // Removed saltValue from settings - it's now managed separately
    defaultViewMode: 'edit' | 'preview';
    showEncryptedExplorer: boolean;
    enableFilenameHover: boolean;
}

const DEFAULT_SETTINGS: Partial<GlobalMarkdownEncryptSettings> = {
    // Removed saltValue from defaults
    defaultViewMode: 'preview',
    showEncryptedExplorer: true,
    enableFilenameHover: true
};

export default class GlobalMarkdownEncrypt extends Plugin {
    public settings: GlobalMarkdownEncryptSettings;
    private aesCipher: any;
    private filenameIndex: Map<string, string> = new Map();
    private encryptedIndex: string = "";
    public isUnlocked: boolean = false;
    private ribbonIcon: HTMLElement | null = null;
    private viewsRegistered: boolean = false; 
    private securePasswordManager: SecurePasswordManager;
	private vaultSalt: string = "";
	public getPasswordManager(): SecurePasswordManager {
	    return this.securePasswordManager;
	}
    public getVaultSalt(): string {
        return this.vaultSalt;
    }
	    
    private async loadFilenameIndex(): Promise<void> {
	    try {
	        const data = await this.loadData();
	        if (data && data.encryptedFilenameIndex && this.aesCipher) {
	            const decryptedIndex = this.aesCipher.decrypt(
	                data.encryptedFilenameIndex.ciphertext,
	                data.encryptedFilenameIndex.iv,
	                data.encryptedFilenameIndex.tag
	            );
	            const indexData = JSON.parse(decryptedIndex);
	            this.filenameIndex = new Map(Object.entries(indexData));
	        }
	    } catch (e) {
	        console.warn('Failed to load filename index:', e);
	        this.filenameIndex = new Map();
	    }
	}

    private async saveFilenameIndex(): Promise<void> {
        try {
            if (!this.aesCipher) return;
            
            const indexData = Object.fromEntries(this.filenameIndex);
            const indexJson = JSON.stringify(indexData);
            
            let [ciphertext, iv, tag] = this.aesCipher.encrypt(indexJson);
            
            const encryptedIndex = {
                iv: iv,
                tag: tag,
                ciphertext: ciphertext
            };
            
            const currentData = await this.loadData() || {};
            currentData.encryptedFilenameIndex = encryptedIndex;
            await this.saveData(currentData);
        } catch (e) {
            console.error('Failed to save filename index:', e);
        }
    }

    public async updateFilenameIndex(filepath: string, displayName: string): Promise<void> {
        if (displayName && displayName.trim()) {
            this.filenameIndex.set(filepath, displayName.trim());
        } else {
            this.filenameIndex.delete(filepath);
        }
        await this.saveFilenameIndex();
        
        this.refreshEncryptedExplorer();
    }

    public async getDisplayName(filepath: string): Promise<string> {
        const displayName = this.filenameIndex.get(filepath);
        if (displayName) {
            return displayName;
        }
        
        const file = this.app.vault.getAbstractFileByPath(filepath);
        return file ? file.name.replace('.aes256', '') : filepath;
    }

    private refreshEncryptedExplorer(): void {
        const leaves = this.app.workspace.getLeavesOfType(VIEW_TYPE_ENCRYPTED_EXPLORER);
        leaves.forEach(leaf => {
            if (leaf.view instanceof EncryptedExplorerView) {
                leaf.view.refresh();
            }
        });
    }

    private async createEncryptedNote(filename?: string) {
        try {
            const newFilename = moment().format(`YYYYMMDD hhmmss[.aes256]`);
            
            const activeFile = this.app.workspace.getActiveFile();
            let newFileFolder: TFolder = this.app.fileManager.getNewFileParent(activeFile ? activeFile.path : '');

            const newFilepath = normalizePath(newFileFolder.path + "/" + newFilename);

            let content = "";
            if (filename && filename.trim()) {
                content = addOrUpdateFrontMatter("", { filename: filename.trim() });
            }

            let [ciphertext, iv, tag] = this.aesCipher.encrypt(content);
            
            const encData = JSON.stringify({
                iv: iv,
                tag: tag,
                ciphertext: ciphertext,
                salt: this.vaultSalt, // Use vault-specific salt
            });

            const file = await this.app.vault.create(newFilepath, encData);
            
            if (filename && filename.trim()) {
                await this.updateFilenameIndex(newFilepath, filename.trim());
            }
            
            const leaf = this.app.workspace.getLeaf(true);
            
            if (this.settings.defaultViewMode === 'edit') {
                await leaf.openFile(file);
            } else {
                await leaf.setViewState({
                    type: VIEW_TYPE_ENCRYPTED_PREVIEW,
                    state: { file: file.path }
                });
            }

        } catch(e) {
            console.error(e);
            new Notice(e);
        }
    }

    private setupFilenameHover(): void {
        if (!this.settings.enableFilenameHover) return;
        
        this.registerDomEvent(document, 'mouseover', (event: MouseEvent) => {
            const target = event.target as HTMLElement;
            
            const fileItem = target.closest('.nav-file-title');
            if (fileItem) {
                const fileNameEl = fileItem.querySelector('.nav-file-title-content');
                if (fileNameEl) {
                    const fileName = fileNameEl.textContent;
                    if (fileName && fileName.endsWith('.aes256')) {
                        const filePath = (fileItem as any).dataset?.path || fileName;
                        const displayName = this.filenameIndex.get(filePath);
                        
                        if (displayName && displayName !== fileName.replace('.aes256', '')) {
                            fileItem.setAttribute('title', `🔒 ${displayName}`);
                        }
                    }
                }
            }
        });
    }

    async onload() {
		await this.loadSettings();
        
        this.securePasswordManager = SecurePasswordManager.getInstance();

	    try {
            this.vaultSalt = await SaltManager.getVaultSalt(this);
        } catch (e) {
            console.error("Failed to get vault salt", e);
            this.vaultSalt = "7f2ea27bd475702540c5211aed17904202a3ac06b0e87fdd8fcdec960a0fe388";
        }
        
        this.addSettingTab(new GlobalMarkdownEncryptSettingTab(this.app, this));
    
        // Only create ribbon icon if it doesn't exist
        if (!this.ribbonIcon) {
            this.ribbonIcon = this.addRibbonIcon('file-lock-2', 'new encrypted note', (evt: MouseEvent) => {
                if (!this.isUnlocked) {
                    new Notice('Please enter password first');
                    this.showPasswordPrompt();
                    return;
                }
                new FilenameInputModal(this.app, (filename) => {
                    this.createEncryptedNote(filename);
                }).open();
            });
            this.ribbonIcon.addClass('gme-new-encrypted-note');
        }
    
        this.registerExtensions(['aes256'], this.settings.defaultViewMode === 'edit' ? VIEW_TYPE_ENCRYPTED_FILE : VIEW_TYPE_ENCRYPTED_PREVIEW);
    
        this.showPasswordPrompt();
    

        this.addCommand({
            id: 'enter-password',
            name: 'Enter encryption password',
            callback: () => {
                this.showPasswordPrompt();
            }
        });

        this.addCommand({
            id: 'switch-encrypted-view-mode',
            name: 'Switch between edit and preview mode',
            callback: () => {
                if (!this.isUnlocked) {
                    new Notice('Please enter password first');
                    return;
                }
                this.switchEncryptedViewMode();
            }
        });

        this.addCommand({
            id: 'create-encrypted-note-with-name',
            name: 'Create encrypted note with custom name',
            callback: () => {
                if (!this.isUnlocked) {
                    new Notice('Please enter password first');
                    return;
                }
                new FilenameInputModal(this.app, (filename) => {
                    this.createEncryptedNote(filename);
                }).open();
            }
        });

        this.addCommand({
            id: 'show-encrypted-explorer',
            name: 'Show encrypted files explorer',
            callback: () => {
                if (!this.isUnlocked) {
                    new Notice('Please enter password first');
                    return;
                }
                this.activateEncryptedExplorer();
            }
        });

        this.addCommand({
            id: 'refresh-filename-index',
            name: 'Refresh filename index',
            callback: async () => {
                if (!this.isUnlocked) {
                    new Notice('Please enter password first');
                    return;
                }
                await this.refreshFilenameIndex();
                new Notice('Filename index refreshed');
            }
        });

        this.registerEvent(this.app.workspace.on('file-menu', (menu: Menu, file: TFile) => {
            if (file.extension === 'aes256') {
                menu.addItem((item) => {
                    item.setTitle('Open in preview mode')
                        .setIcon('eye')
                        .onClick(() => {
                            if (!this.isUnlocked) {
                                new Notice('Please enter password first');
                                return;
                            }
                            const leaf = this.app.workspace.getLeaf(false);
                            leaf.setViewState({
                                type: VIEW_TYPE_ENCRYPTED_PREVIEW,
                                state: { file: file.path }
                            });
                        });
                });
                
                menu.addItem((item) => {
                    item.setTitle('Open in edit mode')
                        .setIcon('edit')
                        .onClick(() => {
                            if (!this.isUnlocked) {
                                new Notice('Please enter password first');
                                return;
                            }
                            const leaf = this.app.workspace.getLeaf(false);
                            leaf.setViewState({
                                type: VIEW_TYPE_ENCRYPTED_FILE,
                                state: { file: file.path, mode: 'source' }
                            });
                        });
                });
                
                menu.addItem((item) => {
                    item.setTitle('Rename encrypted file')
                        .setIcon('pencil')
                        .onClick(() => {
                            if (!this.isUnlocked) {
                                new Notice('Please enter password first');
                                return;
                            }
                            const currentName = this.filenameIndex.get(file.path) || '';
                            new FilenameInputModal(this.app, async (newName) => {
                                await this.updateFilenameIndex(file.path, newName);
                                new Notice(`Renamed to: ${newName}`);
                            }, currentName).open();
                        });
                });
            }
        }));
    }

    private async showPasswordPrompt(): Promise<void> {
        new InputPasswordModal(this.app, async (password) => {
            if (!password) return;
            
            // Store password securely
            this.securePasswordManager.setPassword(password);
            
            try {
                // FIRST: Check if we need to migrate from old salt to new salt
                const oldHardcodedSalt = "7f2ea27bd475702540c5211aed17904202a3ac06b0e87fdd8fcdec960a0fe388";
                const currentVaultSalt = await SaltManager.getVaultSalt(this); // Get NEW salt
                
                let workingSalt = currentVaultSalt; // Default to new salt
                let passwordValid = false;
                
                // Check if we have files encrypted with the old hardcoded salt
                const encryptedFiles = this.app.vault.getFiles().filter(file => file.extension === 'aes256');
                let needsMigration = false;
                
                if (encryptedFiles.length > 0) {
                    // Try to decrypt the first file with the NEW salt
                    try {
                        const testKey = await pbkdf2Async(password, currentVaultSalt, 1000000);
                        const testCipher = aes256gcm(testKey);
                        
                        const content = await this.app.vault.read(encryptedFiles[0]);
                        const encryptedData = JSON.parse(content);
                        testCipher.decrypt(encryptedData.ciphertext, encryptedData.iv, encryptedData.tag);
                        
                        // Success with new salt
                        passwordValid = true;
                        console.log("Files are already using new salt");
                    } catch (e) {
                        // Failed with new salt, try old salt
                        console.log("Failed with new salt, trying old salt...");
                        try {
                            const oldKey = await pbkdf2Async(password, oldHardcodedSalt, 1000000);
                            const oldCipher = aes256gcm(oldKey);
                            
                            const content = await this.app.vault.read(encryptedFiles[0]);
                            const encryptedData = JSON.parse(content);
                            oldCipher.decrypt(encryptedData.ciphertext, encryptedData.iv, encryptedData.tag);
                            
                            // Success with old salt - need migration
                            passwordValid = true;
                            needsMigration = true;
                            workingSalt = oldHardcodedSalt; // Use old salt temporarily
                            console.log("Files are using old salt - migration needed");
                        } catch (e2) {
                            // Failed with both salts
                            this.securePasswordManager.clearPassword();
                            new Notice('Invalid password or corrupted encrypted files', 5000);
                            setTimeout(() => this.showPasswordPrompt(), 100);
                            return;
                        }
                    }
                } else {
                    // No encrypted files - accept any password for new vault
                    passwordValid = true;
                    console.log("No encrypted files found - new vault");
                }
                
                if (passwordValid) {
                    // Create cipher with the working salt (old if migration needed, new otherwise)
                    const workingKey = await pbkdf2Async(password, workingSalt, 1000000);
                    this.aesCipher = aes256gcm(workingKey);
                    this.vaultSalt = workingSalt;
                    this.isUnlocked = true;
                    
                    // If migration is needed, do it now
                    if (needsMigration) {
                        new Notice('Migrating encrypted files to new security standard...', 10000);
                        await this.performMigration(password, oldHardcodedSalt, currentVaultSalt);
                    }
                    
                    // Load filename index and setup views
                    await this.loadFilenameIndex();
                    
                    // Register views
                    this.registerView(VIEW_TYPE_ENCRYPTED_FILE, (leaf) => new EncryptedFileView(leaf, this.aesCipher, this.vaultSalt, this));
                    this.registerView(VIEW_TYPE_ENCRYPTED_PREVIEW, (leaf) => new EncryptedPreviewView(leaf, this.aesCipher, this));
                    this.registerView(VIEW_TYPE_ENCRYPTED_EXPLORER, (leaf) => new EncryptedExplorerView(leaf, this));
                    
                    this.setupFilenameHover();
                    
                    if (this.settings.showEncryptedExplorer) {
                        this.activateEncryptedExplorer();
                    }
                    
                    new Notice('Successfully unlocked encrypted files', 3000);
                }
            } catch (error) {
                this.securePasswordManager.clearPassword();
                console.error('Password verification failed:', error);
                new Notice('Password verification failed. Please try again.', 3000);
                setTimeout(() => this.showPasswordPrompt(), 100);
            }
        }, () => {
            new Notice('Password required to access encrypted files. Use the "Enter encryption password" command to try again.', 5000);
        }).open();
    }

    public showPasswordPromptFromSettings(): void {
        this.showPasswordPrompt();
    }

	private async performMigration(password: string, oldSalt: string, newSalt: string): Promise<void> {
	    try {
	        // Create both ciphers
	        const oldKey = await pbkdf2Async(password, oldSalt, 1000000);
	        const oldCipher = aes256gcm(oldKey);
	        
	        const newKey = await pbkdf2Async(password, newSalt, 1000000);
	        const newCipher = aes256gcm(newKey);
	        
	        // Get all encrypted files
	        const encryptedFiles = this.app.vault.getFiles().filter(f => f.extension === 'aes256');
	        let successCount = 0;
	        
	        console.log(`Migrating ${encryptedFiles.length} encrypted files...`);
	        
	        for (const file of encryptedFiles) {
	            try {
	                console.log(`Migrating ${file.path}...`);
	                const content = await this.app.vault.read(file);
	                const encryptedData = JSON.parse(content);
	                
	                // Decrypt with old cipher
	                const decrypted = oldCipher.decrypt(
	                    encryptedData.ciphertext,
	                    encryptedData.iv,
	                    encryptedData.tag
	                );
	                
	                // Re-encrypt with new cipher (generate new IV)
					const [newCiphertext, newIv, newTag] = newCipher.encrypt(decrypted, null);
						                
	                // Save with new encryption
	                const newEncryptedData = {
	                    iv: newIv,
	                    tag: newTag,
	                    ciphertext: newCiphertext,
	                    salt: newSalt
	                };
	                
	                await this.app.vault.modify(file, JSON.stringify(newEncryptedData, null, 2));
	                successCount++;
	                
	            } catch (e) {
	                console.error(`Failed to migrate ${file.path}:`, e);
	            }
	        }
	        
	        // Update the vault salt and cipher to use the new salt
	        this.vaultSalt = newSalt;
	        const finalKey = await pbkdf2Async(password, newSalt, 1000000);
	        this.aesCipher = aes256gcm(finalKey);
	        
	        new Notice(`Migration complete! ${successCount}/${encryptedFiles.length} files migrated.`, 8000);
	        
	    } catch (error) {
	        console.error('Migration failed:', error);
	        new Notice('Migration failed. Files may be corrupted.', 5000);
	    }
	}
	
    public async refreshFilenameIndex(): Promise<void> {
        const encryptedFiles = this.app.vault.getFiles().filter(file => file.extension === 'aes256');
        
        for (const file of encryptedFiles) {
            try {
                const content = await this.app.vault.read(file);
                const encryptedData = JSON.parse(content);
                const decryptedContent = this.aesCipher.decrypt(
                    encryptedData.ciphertext, 
                    encryptedData.iv, 
                    encryptedData.tag
                );
                
                const { frontMatter } = extractFrontMatter(decryptedContent);
                if (frontMatter.filename) {
                    await this.updateFilenameIndex(file.path, frontMatter.filename);
                }
            } catch (e) {
                console.warn(`Failed to refresh filename for ${file.path}:`, e);
            }
        }
    }

    public activateEncryptedExplorer(): void {
        const existing = this.app.workspace.getLeavesOfType(VIEW_TYPE_ENCRYPTED_EXPLORER);
        if (existing.length > 0) {
            this.app.workspace.revealLeaf(existing[0]);
            return;
        }
        
        this.app.workspace.getRightLeaf(false).setViewState({
            type: VIEW_TYPE_ENCRYPTED_EXPLORER
        });
    }

    switchEncryptedViewMode(): void {
        const activeLeaf = this.app.workspace.activeLeaf;
        if (activeLeaf && activeLeaf.view) {
            const currentView = activeLeaf.view;
            const file = (currentView as any).file;
            
            if (file && file.extension === 'aes256') {
                if (currentView.getViewType() === VIEW_TYPE_ENCRYPTED_FILE) {
                    activeLeaf.setViewState({
                        type: VIEW_TYPE_ENCRYPTED_PREVIEW,
                        state: { file: file.path }
                    });
                } else if (currentView.getViewType() === VIEW_TYPE_ENCRYPTED_PREVIEW) {
                    activeLeaf.setViewState({
                        type: VIEW_TYPE_ENCRYPTED_FILE,
                        state: { file: file.path, mode: 'source' }
                    });
                }
            }
        }
    }

    async loadSettings() {
        this.settings = Object.assign({}, DEFAULT_SETTINGS, await this.loadData());
    }

    async saveSettings(newSettings: GlobalMarkdownEncryptSettings) {
        this.settings = newSettings;
        await this.saveData(newSettings);
    }

    onunload() {
        this.filenameIndex.clear();
        this.isUnlocked = false;
        this.aesCipher = null;
		this.vaultSalt = "";
        
        // Securely clear password from memory
        if (this.securePasswordManager) {
            this.securePasswordManager.clearPassword();
        }
        
        
        // Remove the ribbon icon (FEEDBACK: Still not working)
        if (this.ribbonIcon) {
            this.ribbonIcon.remove();
            this.ribbonIcon = null;
        }
    }
}

export class GlobalMarkdownEncryptSettingTab extends PluginSettingTab {
    plugin: GlobalMarkdownEncrypt;

    constructor(app: App, plugin: GlobalMarkdownEncrypt) {
        super(app, plugin);
        this.plugin = plugin;
    }

    display(): void {
        const { containerEl } = this;
        containerEl.empty();

        new Setting(containerEl)
            .setName("Encryption Status")
            .setDesc(this.plugin.isUnlocked ? "✅ Plugin is unlocked and ready" : "🔒 Plugin is locked - password required")
            .addButton((button) =>
                button
                    .setButtonText(this.plugin.isUnlocked ? "Re-enter Password" : "Enter Password")
                    .setCta()
                    .onClick(() => {
                        this.plugin.showPasswordPromptFromSettings();
                    })
            );

        new Setting(containerEl) // Strictly enforced salt automation. THIS is the Gold standard for salt generation, no user-defined salts.
        .setName("Encryption Salt")
        .setDesc("🔒 This vault uses a unique encryption salt for enhanced security. Salt is automatically generated and managed per vault.")
        .addButton((button) =>
            button
                .setButtonText("View Salt Info")
                .onClick(() => {
                    new Notice(`Vault salt: ${this.plugin.getVaultSalt().substring(0, 16)}...`, 5000);
                })
        );

        new Setting(containerEl)
            .setName("Default view mode")
            .setDesc("Choose whether encrypted files open in edit or preview mode by default")
            .addDropdown((dropdown) =>
                dropdown
                    .addOption('preview', 'Preview (Read-only)')
                    .addOption('edit', 'Edit')
                    .setValue(this.plugin.settings.defaultViewMode)
                    .onChange(async (value: 'edit' | 'preview') => {
                        let newSettings: GlobalMarkdownEncryptSettings = { ...this.plugin.settings };
                        newSettings.defaultViewMode = value;
                        await this.plugin.saveSettings(newSettings);
                    })
            );

        new Setting(containerEl)
            .setName("Show encrypted files explorer")
            .setDesc("Display a dedicated sidebar panel showing all encrypted files with their custom names")
            .addToggle((toggle) =>
                toggle
                    .setValue(this.plugin.settings.showEncryptedExplorer)
                    .onChange(async (value) => {
                        let newSettings: GlobalMarkdownEncryptSettings = { ...this.plugin.settings };
                        newSettings.showEncryptedExplorer = value;
                        await this.plugin.saveSettings(newSettings);
                        
                        if (value && this.plugin.isUnlocked) {
                            this.plugin.activateEncryptedExplorer();
                        }
                    })
            );

        new Setting(containerEl)
            .setName("Enable filename hover tooltips")
            .setDesc("Show custom filenames when hovering over encrypted files in the file explorer")
            .addToggle((toggle) =>
                toggle
                    .setValue(this.plugin.settings.enableFilenameHover)
                    .onChange(async (value) => {
                        let newSettings: GlobalMarkdownEncryptSettings = { ...this.plugin.settings };
                        newSettings.enableFilenameHover = value;
                        await this.plugin.saveSettings(newSettings);
                    })
            );

        new Setting(containerEl)
            .setName("Filename index management")
            .setDesc("Refresh the filename index by scanning all encrypted files")
            .addButton((button) =>
                button
                    .setButtonText("Refresh filename index")
                    .setCta()
                    .onClick(async () => {
                        if (!this.plugin.isUnlocked) {
                            new Notice("Please enter password first");
                            return;
                        }
                        await this.plugin.refreshFilenameIndex();
                        new Notice("Filename index refreshed successfully");
                    })
            );
    }
}

class InputPasswordModal extends Modal {
    onSubmit: (password: string) => void;
    onCancel: (() => void) | undefined;
    password: string;
    cancelled: boolean = false;

    constructor(app: App, onSubmit: (password: string) => void, onCancel?: () => void) {
        super(app);
        this.onSubmit = onSubmit;
        this.onCancel = onCancel;
    }

    onOpen() {
        const { contentEl } = this;
        contentEl.empty();

        contentEl.createEl("h2", { text: "Enter encryption password" });

        const inputPwContainerEl = contentEl.createDiv();
        inputPwContainerEl.style.marginBottom = '1em';
        
        const pwInputEl = inputPwContainerEl.createEl('input', { 
            type: 'password', 
            value: '' 
        });
        pwInputEl.placeholder = "Enter your encryption password";
        pwInputEl.style.width = '100%';
        pwInputEl.style.padding = '8px';
        pwInputEl.focus();

        const buttonContainer = contentEl.createDiv();
        buttonContainer.style.display = 'flex';
        buttonContainer.style.gap = '10px';
        buttonContainer.style.justifyContent = 'flex-end';

        const unlockButton = buttonContainer.createEl('button', { 
            text: 'Unlock', 
            cls: 'mod-cta' 
        });

        const cancelButton = buttonContainer.createEl('button', { 
            text: 'Cancel' 
        });

        const commitPassword = () => {
            this.password = pwInputEl.value;
            this.close();
        };

        const cancelAction = () => {
            this.cancelled = true;
            this.close();
        };

        unlockButton.onclick = commitPassword;
        cancelButton.onclick = cancelAction;

        pwInputEl.addEventListener('keypress', (event) => {
            if (event.key === 'Enter') {
                commitPassword();
            } else if (event.key === 'Escape') {
                cancelAction();
            }
        });

        const warningText = contentEl.createEl('div', { 
            text: 'This password will be used to decrypt all your encrypted notes. Make sure it\'s the same password you used when creating them. You can cancel if you don\'t want to access encrypted files right now.',
            cls: 'setting-item-description'
        });
        warningText.style.marginTop = '10px';
        warningText.style.fontSize = '0.9em';
        warningText.style.color = 'var(--text-muted)';

        this.modalEl.addEventListener('click', (event) => {
            event.stopPropagation();
        });
    }

    onClose() {
        const { contentEl } = this;
        contentEl.empty();

        if (this.cancelled && this.onCancel) {
            this.onCancel();
        } else if (!this.cancelled && this.password) {
            this.onSubmit(this.password);
        }
    }
}

class FilenameInputModal extends Modal {
    onSubmit: (filename: string) => void;
    filename: string;
    initialValue: string;

    constructor(app: App, onSubmit: (filename: string) => void, initialValue: string = '') {
        super(app);
        this.onSubmit = onSubmit;
        this.initialValue = initialValue;
        this.filename = initialValue;
    }

    onOpen() {
        const { contentEl } = this;
        contentEl.empty();

        contentEl.createEl("h2", { text: "Enter filename for encrypted note" });

        const inputContainer = contentEl.createDiv();
        inputContainer.style.marginBottom = '1em';
        
        const filenameInput = inputContainer.createEl('input', { 
            type: 'text', 
            value: this.initialValue,
            placeholder: 'Enter a descriptive name for your encrypted note'
        });
        filenameInput.style.width = '100%';
        filenameInput.style.padding = '8px';
        filenameInput.style.marginBottom = '10px';
        filenameInput.focus();

        const buttonContainer = contentEl.createDiv();
        buttonContainer.style.display = 'flex';
        buttonContainer.style.gap = '10px';
        buttonContainer.style.justifyContent = 'flex-end';

        const createButton = buttonContainer.createEl('button', { 
            text: this.initialValue ? 'Update' : 'Create', 
            cls: 'mod-cta' 
        });
        
        const cancelButton = buttonContainer.createEl('button', { 
            text: 'Cancel' 
        });

        const commitFilename = () => {
            this.filename = filenameInput.value.trim();
            this.close();
        };

        const cancelAction = () => {
            this.filename = '';
            this.close();
        };

        createButton.onclick = commitFilename;
        cancelButton.onclick = cancelAction;

        filenameInput.addEventListener('keypress', (event) => {
            if (event.key === 'Enter') {
                commitFilename();
            } else if (event.key === 'Escape') {
                cancelAction();
            }
        });

        const helpText = contentEl.createEl('div', { 
            text: 'This name will be stored in the file\'s metadata and shown in the UI instead of the timestamp-based filename.',
            cls: 'setting-item-description'
        });
        helpText.style.marginTop = '10px';
        helpText.style.fontSize = '0.9em';
        helpText.style.color = 'var(--text-muted)';
    }

    onClose() {
        const { contentEl } = this;
        contentEl.empty();

        if (this.filename) {
            this.onSubmit(this.filename);
        }
    }
}
