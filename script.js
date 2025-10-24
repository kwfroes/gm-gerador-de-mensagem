document.addEventListener('DOMContentLoaded', function () {
    // --- INFORMAÇÕES DA APLICAÇÃO ---
    /**
     * @functionality 501
     * @category 5xx: Utilitários e Validações
     * @name Definição de Constantes de Aplicação e Versão
     * @description Armazena autor, nome, versão e data para footer e logs.
     */
    const APP_AUTHOR = "Kevin Fróes";
    const APP_NAME = "Gerador de Mensagens";
    const APP_VERSION = "2.9.5";
    const APP_VERSION_DATE = "24/10/2025";

    // --- VARIÁVEIS DE ESTADO ---
    let db;
    let encryptionKey = null;
    let titleClickCount = 0;

    // --- ELEMENTOS DO DOM ---
    /**
     * @functionality 407
     * @category 4xx: UI/UX e Interações
     * @name Seleção de Elementos DOM com Cache para Performance
     * @description Armazena referências a inputs, modais e botões em variáveis globais.
     */
    const dbName = "CafDatabase";
    const dbVersion = 5;
    const dbStatus = document.getElementById('db-status');
    const familyDbStatus = document.getElementById('family-db-status');
    const cnpjInputForDb = document.getElementById('cnpj');
    const companyNameInputForDb = document.getElementById('companyName');
    const companyNameResults = document.getElementById('companyNameResults');
    const cnpjStatusSpan = document.getElementById('cnpj-status');
    const appTitle = document.getElementById('appTitle');
    const dbModal = document.getElementById('dbModal');
    const openDbModalBtn = document.getElementById('openDbModalBtn');
    const closeDbModalBtn = document.getElementById('closeDbModalBtn');
    const historyModal = document.getElementById('historyModal');
    const openHistoryModalBtn = document.getElementById('openHistoryModalBtn');
    const closeHistoryModalBtn = document.getElementById('closeHistoryModalBtn');
    const exportModal = document.getElementById('exportModal');
    const confirmExportBtn = document.getElementById('confirmExportBtn');
    const cancelExportBtn = document.getElementById('cancelExportBtn');
    const passwordModal = document.getElementById('passwordModal');
    const passwordForm = document.getElementById('passwordForm');
    const masterPasswordInput = document.getElementById('masterPassword');
    const keepLoggedInCheckbox = document.getElementById('keepLoggedIn');
    const passwordPromptMessage = document.getElementById('passwordPromptMessage');
    const logoutBtn = document.getElementById('logoutBtn');
    const csvFileInput = document.getElementById('csvFileInput');
    const loadCsvBtn = document.getElementById('loadCsvBtn');
    const loginBtn = document.getElementById('loginBtn');
    const csvFileInputLabel = document.getElementById('csvFileInputLabel');
    const familyCsvFileInput = document.getElementById('familyCsvFileInput');
    const loadFamilyCsvBtn = document.getElementById('loadFamilyCsvBtn');
    const familyCsvFileInputLabel = document.getElementById('familyCsvFileInputLabel');
    const historySearchCnpj = document.getElementById('historySearchCnpj');
    const historyStartDate = document.getElementById('historyStartDate');
    const historyEndDate = document.getElementById('historyEndDate');
    const filterHistoryBtn = document.getElementById('filterHistoryBtn');
    const clearHistoryFilterBtn = document.getElementById('clearHistoryFilterBtn');


    // --- MODAL DE BACKUP ---
    const backupReminderModal = document.getElementById('backupReminderModal');
    const backupReminderPeriodSelect = document.getElementById('backupReminderPeriod');
    const confirmBackupReminderBtn = document.getElementById('confirmBackupReminderBtn');
    const cancelBackupReminderBtn = document.getElementById('cancelBackupReminderBtn');
    const closeBackupReminderBtn = document.getElementById('closeBackupReminderBtn');

    // --- MODAL WPP ---
    const sendWppBtn = document.getElementById('sendWppBtn');
    const wppModal = document.getElementById('wppModal');
    const closeWppModalBtn = document.getElementById('closeWppModalBtn');
    const wppContactListContainer = document.getElementById('wppContactListContainer');
    
    // Elementos do Modal de DB para Contatos
    const addContactBtn = document.getElementById('addContactBtn');
    const contactsListContainer = document.getElementById('contactsListContainer');
    const loadContactsCsvBtn = document.getElementById('loadContactsCsvBtn');
    const exportContactsCsvBtn = document.getElementById('exportContactsCsvBtn');
    const contactsCsvFileInput = document.getElementById('contactsCsvFileInput');
    const contactsDbStatus = document.getElementById('contacts-db-status');
    const modalcontactNameInput = document.getElementById('contactNameInput');
    const modalcontactRoleInput = document.getElementById('contactRoleInput');
    const contactPhoneInput = document.getElementById('contactPhoneInput');
    const contactsModal = document.getElementById('contactsModal');
    const openContactsModalBtn = document.getElementById('openContactsModalBtn');
    const closeContactsModalBtn = document.getElementById('closeContactsModalBtn');

    // --- FUNÇÕES GERAIS E DE UTILIDADE ---

    /**
     * @functionality 401
     * @category 4xx: UI/UX e Interações
     * @name Sistema de Notificações Toast com Transições CSS e Tipos Semânticos
     * @description Exibe mensagens temporárias (sucesso/erro/info) no canto inferior direito.
     */
    function showToast(message, type = 'info') {
        const toast = document.getElementById('toast');
        toast.textContent = message;
        toast.classList.remove('bg-green-600', 'bg-red-600', 'bg-black');
        if (type === 'success') toast.classList.add('bg-green-600');
        else if (type === 'error') toast.classList.add('bg-red-600');
        else toast.classList.add('bg-black');
        toast.classList.remove('opacity-0');
        setTimeout(() => toast.classList.add('opacity-0'), 3000);
    }
    
    /**
     * @functionality 416
     * @category 4xx: UI/UX e Interações
     * @name Renderização de Footer com Versão e Botão de Logout Condicional
     * @description Mostra info de app e esconde/mostra logout baseado em autenticação.
     */
    function renderFooter() {
        const footer = document.getElementById('appVersionInfo');
        if (footer) footer.textContent = `${APP_AUTHOR} - ${APP_NAME} Versão ${APP_VERSION} de ${APP_VERSION_DATE}`;
    }

    /**
     * @functionality 103
     * @category 1xx: Criptografia e Segurança
     * @name Escapamento de HTML em Renderização de Histórico para Prevenção de XSS
     * @description Usa escapeHtml para sanitizar mensagens no histórico.
     */
    function escapeHtml(text) {
        if (typeof text !== 'string') return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    /**
     * @functionality 503
     * @category 5xx: Utilitários e Validações
     * @name Formatação de Máscara Dinâmica de CNPJ/CPF
     * @description Aplica máscara de CPF (11) ou CNPJ (14) a uma string de dígitos.
     */
    function formatDocument(v) {
        v = v.replace(/\D/g, ''); // Remove tudo que não é dígito
        
        if (v.length <= 11) { // Formato CPF
            v = v.replace(/(\d{3})(\d)/, '$1.$2');
            v = v.replace(/(\d{3})(\d)/, '$1.$2');
            v = v.replace(/(\d{3})(\d{1,2})$/, '$1-$2');
        } else { // Formato CNPJ
            v = v.replace(/^(\d{2})(\d)/, '$1.$2');
            v = v.replace(/^(\d{2})\.(\d{3})(\d)/, '$1.$2.$3');
            v = v.replace(/\.(\d{3})(\d)/, '.$1/$2');
            v = v.replace(/(\d{4})(\d)/, '$1-$2');
        }
        return v;
    }

    // --- LÓGICA DE CRIPTOGRAFIA ---

    /**
     * @functionality 100
     * @category 1xx: Criptografia e Segurança
     * @name Implementação de Criptografia AES-GCM com PBKDF2
     * @description Deriva chaves de senha via PBKDF2 e prepara para criptografia AES-GCM.
     */
    async function deriveKey(password, salt) {
        const encoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            encoder.encode(password),
            { name: 'PBKDF2' },
            false,
            ['deriveKey']
        );
        return crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );
    }

    /**
     * @functionality 100
     * @category 1xx: Criptografia e Segurança
     * @name Implementação de Criptografia AES-GCM com PBKDF2
     * @description Criptografa dados com AES-GCM (IV aleatório). Corrige stack overflow processando em chunks.
     */
    async function encryptData(text, key) {
        const encoder = new TextEncoder();
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encryptedContent = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            key,
            encoder.encode(text)
        );
        const encryptedBytes = new Uint8Array(encryptedContent);
        const finalData = new Uint8Array(iv.length + encryptedBytes.length);
        finalData.set(iv);
        finalData.set(encryptedBytes, iv.length);
        
        let binaryString = '';
        const CHUNK_SIZE = 8192;
        for (let i = 0; i < finalData.length; i += CHUNK_SIZE) {
            const chunk = finalData.subarray(i, i + CHUNK_SIZE);
            binaryString += String.fromCharCode.apply(null, chunk);
        }
        return btoa(binaryString);
    }

    /**
     * @functionality 100
     * @category 1xx: Criptografia e Segurança
     * @name Implementação de Criptografia AES-GCM com PBKDF2
     * @description Descriptografa dados com AES-GCM.
     */
    async function decryptData(encryptedText, key) {
        const binaryString = atob(encryptedText);
        const encryptedDataWithIv = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            encryptedDataWithIv[i] = binaryString.charCodeAt(i);
        }
        
        const iv = encryptedDataWithIv.slice(0, 12);
        const encryptedContent = encryptedDataWithIv.slice(12);
        const decryptedContent = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv },
            key,
            encryptedContent
        );
        const decoder = new TextDecoder();
        return decoder.decode(decryptedContent);
    }

    // --- LÓGICA DE AUTENTICAÇÃO E SESSÃO ---

    /**
     * @functionality 101
     * @category 1xx: Criptografia e Segurança
     * @name Mecanismo de Derivação e Armazenamento de Chave de Sessão no Navegador
     * @description Importa/exporta chaves JWK para localStorage/sessionStorage, com fallback para senha mestra. Suporta "manter conectado".
     */
    async function handlePasswordSubmit(event) {
        event.preventDefault();
        const password = masterPasswordInput.value;
        if (!password) return;

        showToast('Processando senha...', 'info');
        
        try {
            const salt = new TextEncoder().encode('caf-app-salt');
            const key = await deriveKey(password, salt);
            
            encryptionKey = key;
            
            const exportableKey = await crypto.subtle.exportKey('jwk', key);
            
            if (keepLoggedInCheckbox.checked) {
                localStorage.setItem('encryptionKey', JSON.stringify(exportableKey));
            } else {
                sessionStorage.setItem('encryptionKey', JSON.stringify(exportableKey));
            }

            passwordModal.classList.add('hidden');
            masterPasswordInput.value = '';
            logoutBtn.classList.remove('hidden');
            loginBtn.classList.add('hidden');

            initializeAppLogic();

        } catch (e) {
            showToast('Erro ao processar a senha.', 'error');
        }
    }
    
    /**
     * @functionality 403
     * @category 4xx: UI/UX e Interações
     * @name Logout e Limpeza de Sessão com Recarregamento de Página
     * @description Remove chaves de storage e recarrega para resetar estado.
     */
    function handleLogout() {
        localStorage.removeItem('encryptionKey');
        sessionStorage.removeItem('encryptionKey');
        location.reload();
    }
    
    /**
     * @functionality 101
     * @category 1xx: Criptografia e Segurança
     * @name Mecanismo de Derivação e Armazenamento de Chave de Sessão no Navegador
     * @description Recupera a chave JWK do localStorage ou sessionStorage e a importa para uso.
     */
    async function getStoredKey() {
        const keyData = localStorage.getItem('encryptionKey') || sessionStorage.getItem('encryptionKey');
        if (!keyData) return null;
        
        try {
            const jwk = JSON.parse(keyData);
            return await crypto.subtle.importKey(
                'jwk',
                jwk,
                { name: 'AES-GCM' },
                true,
                ['encrypt', 'decrypt']
            );
        } catch (e) {
            return null;
        }
    }

    // --- LÓGICA DE HASH E VERIFICAÇÃO DE ATUALIZAÇÃO ---

    /**
     * @functionality 209
     * @category 2xx: Banco de Dados e Persistência
     * @name Gerenciamento de Configurações de Backup Pessoal no Metadata
     * @description Salva o período (ms) selecionado pelo usuário no metadata store.
     */
    function saveBackupReminderPeriod(periodMs) {
        return new Promise((resolve, reject) => {
            if (!db) return reject('DB not available');
            const transaction = db.transaction(['metadata'], 'readwrite');
            const store = transaction.objectStore('metadata');
            const request = store.put({ id: 'backup_reminder_period', value: periodMs });
            request.onsuccess = () => resolve();
            request.onerror = (e) => reject(e.target.error);
        });
    }

    /**
     * @functionality 209
     * @category 2xx: Banco de Dados e Persistência
     * @name Gerenciamento de Configurações de Backup Pessoal no Metadata
     * @description Recupera o período (ms) do metadata store. Padrão: Diariamente (86400000).
     */
    function getBackupReminderPeriod() {
        return new Promise((resolve) => {
            if (!db) return resolve(86400000); // Padrão
            const transaction = db.transaction(['metadata'], 'readonly');
            const store = transaction.objectStore('metadata');
            const request = store.get('backup_reminder_period');
            request.onsuccess = () => {
                // Padrão é 'Diariamente' (86400000) se não estiver definido
                resolve(request.result ? request.result.value : 86400000); 
            };
            request.onerror = () => resolve(86400000); // Padrão em caso de erro
        });
    }

    /**
     * @functionality 209
     * @category 2xx: Banco de Dados e Persistência
     * @name Gerenciamento de Configurações de Backup Pessoal no Metadata
     * @description Salva o timestamp (Date.now()) do último backup pessoal realizado.
     */
    function updateLastPersonalBackupTimestamp(timestamp) {
         return new Promise((resolve, reject) => {
            if (!db) return reject('DB not available');
            const transaction = db.transaction(['metadata'], 'readwrite');
            const store = transaction.objectStore('metadata');
            const request = store.put({ id: 'last_personal_backup', value: timestamp });
            request.onsuccess = () => resolve();
            request.onerror = (e) => reject(e.target.error);
        });
    }

    /**
     * @functionality 209
     * @category 2xx: Banco de Dados e Persistência
     * @name Gerenciamento de Configurações de Backup Pessoal no Metadata
     * @description Recupera o timestamp do último backup pessoal. Padrão: 0.
     */
    function getLastPersonalBackupTimestamp() {
         return new Promise((resolve) => {
            if (!db) return resolve(0);
            const transaction = db.transaction(['metadata'], 'readonly');
            const store = transaction.objectStore('metadata');
            const request = store.get('last_personal_backup');
            request.onsuccess = () => resolve(request.result ? request.result.value : 0);
            request.onerror = () => resolve(0);
        });
    }



    /**
     * @functionality 102
     * @category 1xx: Criptografia e Segurança
     * @name Cálculo de Hash SHA-256 para Detecção de Mudanças em Backups
     * @description Gera hash hexadecimal de strings JSON para comparação remota/local.
     */
    async function calculateHash(text) {
        const encoder = new TextEncoder();
        const data = encoder.encode(text);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        return hashHex;
    }

    /**
     * @functionality 207
     * @category 2xx: Banco de Dados e Persistência
     * @name Armazenamento e Recuperação de Hash Local em Store de Metadados
     * @description Recupera hash de backups no store 'metadata' para verificações.
     */
    function getLocalHash() {
        return new Promise((resolve) => {
            if (!db) return resolve(null);
            const transaction = db.transaction(['metadata'], 'readonly');
            const store = transaction.objectStore('metadata');
            const request = store.get('backup_hash');
            request.onsuccess = () => resolve(request.result ? request.result.value : null);
            request.onerror = () => resolve(null);
        });
    }

    /**
     * @functionality 207
     * @category 2xx: Banco de Dados e Persistência
     * @name Armazenamento e Recuperação de Hash Local em Store de Metadados
     * @description Salva hash de backups no store 'metadata' para verificações.
     */
    function saveLocalHash(hash) {
        return new Promise((resolve, reject) => {
            if (!db) return reject('DB not available');
            const transaction = db.transaction(['metadata'], 'readwrite');
            const store = transaction.objectStore('metadata');
            const request = store.put({ id: 'backup_hash', value: hash });
            request.onsuccess = () => resolve();
            request.onerror = (e) => reject(e.target.error);
        });
    }

    /**
     * @functionality 202
     * @category 2xx: Banco de Dados e Persistência
     * @name Verificação Automática de Atualizações via Hash SHA-256 de Backup Criptografado
     * @description Fetch backup.json, descriptografa, compara hashes locais/remotos e importa se difere.
     */
    async function checkForUpdates() {
        if (!encryptionKey) return;

        try {
            const response = await fetch('backup.json');
            if (!response.ok) {
                console.warn('Arquivo de backup central não encontrado. Pulando verificação automática.');
                const localHash = await getLocalHash();
                if (!localHash) { 
                    showToast('Arquivo "backup.json" não encontrado na pasta.', 'error');
                }
                return;
            }

            const encryptedText = await response.text();
            
            const jsonText = await decryptData(encryptedText, encryptionKey);
            
            const remoteHash = await calculateHash(jsonText);
            const localHash = await getLocalHash();
            
            if (remoteHash !== localHash) {
                if(localHash === null){
                    showToast('Base de dados inicial encontrada. Carregando...', 'info');
                } else {
                    showToast('Nova base de dados encontrada. Atualizando...', 'info');
                }
                const data = JSON.parse(jsonText);
                await processImportData(data, remoteHash);
            }
        } catch (error) {
            console.error('Falha na verificação de atualização:', error);
            showToast('Falha ao verificar/descriptografar base de dados.', 'error');
            handleLogout();
        }
    }

    // --- LÓGICA DO MODO ADMIN ---
    
/**
 * @functionality 410
 * @name Atualização de Estado dos Controles de Admin
 * @description Habilita/desabilita todas as funcionalidades de admin (exportação e upload de CSV)
 */
function updateAdminControlsState() {
    const isAdmin = sessionStorage.getItem('adminModeUnlocked') === 'true';
    
    // Controles de Exportação
    const exportCompanies = document.getElementById('exportCompanies');
    const exportFamilies = document.getElementById('exportFamilies');
    
    [exportCompanies, exportFamilies].forEach(checkbox => {
        checkbox.disabled = !isAdmin;
        const label = checkbox.closest('label');
        if (isAdmin) {
            label.classList.remove('opacity-50', 'cursor-not-allowed');
            label.title = '';
        } else {
            label.classList.add('opacity-50', 'cursor-not-allowed');
            label.title = 'Opção disponível apenas no Modo Admin.';
        }
    });

    const exportHistory = document.getElementById('exportHistory');
    const exportContacts = document.getElementById('exportContacts');
    
    if (isAdmin) {
        exportCompanies.checked = true;
        exportFamilies.checked = true;
        exportHistory.checked = false;
        exportContacts.checked = false;
    } else {
        exportCompanies.checked = false;
        exportFamilies.checked = false;
        exportHistory.checked = true;
        exportContacts.checked = true;
    }
    
    // Controles de Upload de CSV
    const csvControls = [
        { input: csvFileInput, btn: loadCsvBtn, label: csvFileInputLabel },
        { input: familyCsvFileInput, btn: loadFamilyCsvBtn, label: familyCsvFileInputLabel }
    ];

    csvControls.forEach(control => {
        control.input.disabled = !isAdmin;
        control.btn.disabled = !isAdmin;
        if (isAdmin) {
            [control.input, control.btn, control.label].forEach(el => el.classList.remove('opacity-50', 'cursor-not-allowed'));
        } else {
            [control.input, control.btn, control.label].forEach(el => el.classList.add('opacity-50', 'cursor-not-allowed'));
        }
    });
    }
    /**
     * @functionality 104
     * @category 1xx: Criptografia e Segurança
     * @name Ativação de Modo Admin via Contador de Cliques com Persistência em SessionStorage
     * @description Desbloqueia exportações completas após 7 cliques no título; atualiza UI de checkboxes.
     * @functionality 105
     * @name Timeout de Contador de Cliques no Título para Ativação Admin
     * @description Reseta titleClickCount após 2s para evitar ativações acidentais.
     */
    function setupAdminModeToggle() {
        appTitle.addEventListener('click', () => {
            titleClickCount++;
            if (titleClickCount >= 7) {
                sessionStorage.setItem('adminModeUnlocked', 'true');
                showToast('Modo Admin Ativado!', 'success');
                updateAdminControlsState(); // Atualiza todos os controles de admin
                titleClickCount = 0;
            }
            setTimeout(() => { titleClickCount = 0; }, 2000);
        });
    }

    // --- INICIALIZAÇÃO E LÓGICA DO BANCO DE DADOS ---
    
    /**
     * @functionality 502
     * @category 5xx: Utilitários e Validações
     * @name Inicialização de Lógica do App Após Autenticação
     * @description Chama checkForUpdates e checkDbStatus após login ou bootstrapping.
     */
    async function initializeAppLogic() {
        await checkForUpdates();
        checkDbStatus('companies', dbStatus, 'registros');
        checkDbStatus('families', familyDbStatus, 'famílias');

        renderContactsList();
        await checkForBackupReminder();
    }

    /**
     * @functionality 504
     * @category 5xx: Utilitários e Validações
     * @name Verificação de Lembrete de Backup na Inicialização
     * @description Compara o último backup pessoal com o período configurado e exibe o modal se vencido.
     */
    async function checkForBackupReminder() {
        if (!encryptionKey) return; // Só verifica se estiver logado

        try {
            const periodMs = Number(await getBackupReminderPeriod());
            if (periodMs === 0) return; // Usuário desativou os lembretes

            const lastBackupTimestamp = await getLastPersonalBackupTimestamp();
            const now = Date.now();

            if ((lastBackupTimestamp + periodMs) < now) {
                // Backup está vencido!
                backupReminderModal.classList.remove('hidden');
            }
        } catch (error) {
            console.error('Erro ao verificar lembrete de backup:', error);
        }
    }

    /**
     * @functionality 200
     * @category 2xx: Banco de Dados e Persistência
     * @name Inicialização e Upgrade de Schema no IndexedDB com Stores Múltiplos
     * @description Cria stores (companies, families, metadata, history) com índices (ex: timestamp). Versão 4 para compatibilidade.
     * @functionality 415
     * @name Prompt de Senha Mestra com Mensagem Dinâmica para Bootstrapping
     * @description Altera texto do modal baseado em presença de backup.json.
     */
    async function initDb() {
        const request = indexedDB.open(dbName, dbVersion);

        request.onupgradeneeded = function(event) {
            db = event.target.result;
            if (!db.objectStoreNames.contains('companies')) db.createObjectStore("companies", { keyPath: "cnpj" });
            if (!db.objectStoreNames.contains('families')) db.createObjectStore("families", { keyPath: "id" });
            if (!db.objectStoreNames.contains('metadata')) db.createObjectStore("metadata", { keyPath: "id" });
            if (!db.objectStoreNames.contains('history')) {
                const historyStore = db.createObjectStore("history", { keyPath: "id", autoIncrement: true });
                historyStore.createIndex("timestamp", "timestamp", { unique: false });
            }

            if (!db.objectStoreNames.contains('contacts')) {
                const contactsStore = db.createObjectStore("contacts", { keyPath: "id", autoIncrement: true });
                contactsStore.createIndex("name", "name", { unique: false });
            }
        };

        request.onsuccess = async function(event) {
            db = event.target.result;

            encryptionKey = await getStoredKey();

            if (encryptionKey) {
                // --- ESTÁ LOGADO ---
                logoutBtn.classList.remove('hidden');
                loginBtn.classList.add('hidden');
                initializeAppLogic();
            } else {
                // --- NÃO ESTÁ LOGADO ---
                logoutBtn.classList.add('hidden');
                loginBtn.classList.remove('hidden');
                
                // Prepara a mensagem do modal, mas não o abre
                try {
                    const response = await fetch('backup.json');
                    if (response.ok) {
                        passwordPromptMessage.textContent = "Uma base de dados central foi encontrada. Por favor, insira a senha mestra para acessá-la.";
                    } else {
                        passwordPromptMessage.textContent = "Por favor, insira a senha mestra para descriptografar e carregar os dados."; // Mensagem padrão
                        console.log("Nenhum backup central encontrado. Iniciando em modo de bootstrapping.");
                    }
                } catch (error) {
                    passwordPromptMessage.textContent = "Por favor, insira a senha mestra para descriptografar e carregar os dados."; // Mensagem padrão
                    console.log("Não foi possível acessar o backup central. Iniciando em modo offline/bootstrapping.");
                }
                
                // Não chame initializeAppLogic() aqui, pois ele será chamado
                // dentro de handlePasswordSubmit() após o login bem-sucedido.
            }
        };

        request.onerror = function(event) {
            showToast('Erro crítico ao acessar o banco de dados local.', 'error');
        };
    }

    /**
     * @functionality 206
     * @category 2xx: Banco de Dados e Persistência
     * @name Contador de Registros e Exibição de Status de DB com Timestamps
     * @description Conta itens em stores e mostra contagem + última atualização via metadados.
     */
    function checkDbStatus(storeName, statusElement, label) {
        if (!db) return;
        try {
            const transaction = db.transaction([storeName], "readonly");
            const objectStore = transaction.objectStore(storeName);
            const countRequest = objectStore.count();

            countRequest.onsuccess = function() {
                const count = countRequest.result;
                if (count > 0) {
                     const metaTransaction = db.transaction(['metadata'], 'readonly');
                     const metaStore = metaTransaction.objectStore('metadata');
                     const timestampRequest = metaStore.get(`${storeName}_last_updated`);

                     timestampRequest.onsuccess = function() {
                         let statusText = `${count} ${label} carregadas.`;
                         if (timestampRequest.result) {
                             statusText += `<br>Última atualização: ${timestampRequest.result.value}`;
                         }
                         statusElement.innerHTML = statusText;
                         statusElement.className = 'text-green-600 text-xs text-center';
                     }
                } else {
                    statusElement.textContent = `Nenhum registro de ${label}.`;
                    statusElement.className = 'text-yellow-600 text-sm';
                }
            }
        } catch (e) {
             statusElement.textContent = 'Erro ao verificar base de dados.';
             statusElement.className = 'text-red-600';
        }
    }
    
    /**
     * @functionality 201
     * @category 2xx: Banco de Dados e Persistência
     * @name Carregamento e Parsing de CSV para Stores Específicos com Delimitador Customizado
     * @description Lê ISO-8859-1, parseia linhas (companyParser/familyParser), limpa store e atualiza metadados com timestamp.
     */
    function loadCsvToDB(file, storeName, statusElement, parser) {
        if (!encryptionKey) {
            showToast('Por favor, faça login antes de carregar dados.', 'error');
            return;
        }
        if (!file) {
            alert('Por favor, selecione um arquivo CSV.');
            return;
        }

        const reader = new FileReader();
        reader.onload = function(event) {
            const lines = event.target.result.split('\n');
            const totalLines = lines.length;
            statusElement.textContent = `Processando ${totalLines} linhas...`;
            statusElement.className = 'text-blue-600';

            const transaction = db.transaction([storeName], "readwrite");
            const objectStore = transaction.objectStore(storeName);
            objectStore.clear();

            lines.forEach((line, index) => {
                const record = parser(line);
                if(record) objectStore.put(record);
            });

            transaction.oncomplete = function() {
                const metaTransaction = db.transaction(['metadata'], 'readwrite');
                const metaStore = metaTransaction.objectStore('metadata');
                const now = new Date();
                const timestamp = now.toLocaleString('pt-BR', { dateStyle: 'short', timeStyle: 'medium' });
                metaStore.put({ id: `${storeName}_last_updated`, value: timestamp });

                metaTransaction.oncomplete = function() {
                    checkDbStatus(storeName, statusElement, storeName === 'companies' ? 'registros' : 'famílias');
                    showToast(`Base de ${storeName} carregada com sucesso!`, 'success');
                }
            };
            transaction.onerror = function() {
                statusElement.textContent = 'Erro ao salvar dados.';
                statusElement.className = 'text-red-600';
                showToast(`Erro ao carregar base de ${storeName}.`, 'error');
            };
        };
        reader.readAsText(file, 'ISO-8859-1');
    }

    /**
     * @functionality 400
     * @category 4xx: UI/UX e Interações
     * @name Exportação e Importação de Backup JSON com Opções Seletivas e Criptografia
     * @description Serializa stores selecionados, criptografa e baixa; suporta admin mode.
     * @functionality 408
     * @name Download de Arquivo de Backup com Blob e URL Temporária
     * @description Cria Blob criptografado e trigger download via hidden.
     */
    async function processExport(options) {
        if (!db) {
            showToast('Banco de dados não está pronto.', 'error');
            return;
        }

        if (!encryptionKey) {
            passwordPromptMessage.textContent = "Esta é a primeira exportação. Crie a senha mestra para proteger o novo arquivo de backup.";
            keepLoggedInCheckbox.checked = true;
            passwordModal.classList.remove('hidden');
            
            passwordForm.addEventListener('submit', () => {
                showToast('Senha criada! Por favor, clique em Exportar novamente para gerar o arquivo.', 'info');
            }, { once: true });
            
            return;
        }
        
        try {
            const storesToExport = [];
            if (options.includeCompanies) storesToExport.push('companies');
            if (options.includeFamilies) storesToExport.push('families');
            if (options.includeHistory) {
                storesToExport.push('history');
            }
            if (options.includeContacts) {
                storesToExport.push('contacts');
            }
            if (storesToExport.length === 0) {
                showToast('Nenhum dado selecionado para exportar.', 'error');
                return;
            }
            storesToExport.push('metadata');

            const exportObj = {};
            const transaction = db.transaction(storesToExport, 'readonly');
            for (const storeName of storesToExport) {
                const store = transaction.objectStore(storeName);
                const allRecords = await new Promise((resolve, reject) => {
                    store.getAll().onsuccess = e => resolve(e.target.result);
                    store.getAll().onerror = e => reject(e.target.error);
                });
                exportObj[storeName] = allRecords;
            }

            const jsonString = JSON.stringify(exportObj, null, 2);
            const encryptedText = await encryptData(jsonString, encryptionKey);

            const blob = new Blob([encryptedText], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            
            let filename = "backup.json";
            let toastMessage = 'Backup de sincronização exportado como "backup.json"!';
            
            if (options.includeHistory || options.includeContacts) {
                const date = new Date().toISOString().slice(0, 10);
                filename = `full_backup_${date}.json`;
                toastMessage = `Backup pessoal completo exportado como "${filename}"!`;
            } else {
                const newHash = await calculateHash(jsonString);
                await saveLocalHash(newHash);
            }
            
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            a.click();
            URL.revokeObjectURL(url);
            showToast(toastMessage, 'success');
        } catch (error) {
            console.error('Erro ao exportar:', error);
            showToast('Falha ao exportar o backup.', 'error');
        }
    }

    /**
     * @functionality 208
     * @category 2xx: Banco de Dados e Persistência
     * @name Processamento de Importação de Backup com Merge e Atualização de Hash
     * @description Descriptografa JSON, insere/atualiza stores e salva novo hash local.
     */
    function processImportData(data, fileHash) {
        return new Promise((resolve, reject) => {
            const storesToImport = Object.keys(data);
            if (storesToImport.length === 0) {
                showToast('Arquivo de backup inválido ou vazio.', 'error');
                return reject('Arquivo inválido');
            }

            const transaction = db.transaction(storesToImport, 'readwrite');
            transaction.oncomplete = () => {
                saveLocalHash(fileHash).then(() => {
                    showToast('Dados restaurados com sucesso!', 'success');
                    checkDbStatus('companies', dbStatus, 'registros');
                    checkDbStatus('families', familyDbStatus, 'famílias');
                    renderContactsList();
                    resolve();
                });
            };
            transaction.onerror = (err) => {
                console.error('Erro na transação de importação:', err);
                showToast('Erro ao restaurar os dados.', 'error');
                reject(err);
            };

            for (const storeName of storesToImport) {
                if (db.objectStoreNames.contains(storeName)) {
                    const store = transaction.objectStore(storeName);
                    store.clear();
                    data[storeName].forEach(record => {
                        store.put(record);
                    });
                }
            }
        });
    }

    /**
     * @functionality 409
     * @category 4xx: UI/UX e Interações
     * @name Importação de Arquivo JSON com Descriptografia e Validação
     * @description Lê arquivo, descriptografa e processa via processImportData.
     */
    async function importDatabase(event) {
        const file = event.target.files[0];
        if (!file || !encryptionKey) {
            if(!encryptionKey) showToast('Por favor, faça login antes de importar.', 'error');
            return;
        };

        const importStatus = document.getElementById('importStatus');
        const importLabel = document.getElementById('importDbLabel');
        const exportBtn = document.getElementById('exportDbBtn');
        
        importStatus.textContent = 'Importando... Por favor, aguarde.';
        importLabel.classList.add('opacity-50', 'cursor-not-allowed');
        exportBtn.disabled = true;

        try {
            const encryptedText = await file.text();
            const jsonText = await decryptData(encryptedText, encryptionKey);
            const data = JSON.parse(jsonText);
            const fileHash = await calculateHash(jsonText);
            await processImportData(data, fileHash);
        } catch (error) {
            console.error('Erro ao importar manualmente:', error);
            showToast('Falha ao ler ou descriptografar o backup.', 'error');
        } finally {
            event.target.value = ''; 
            importStatus.textContent = '';
            importLabel.classList.remove('opacity-50', 'cursor-not-allowed');
            exportBtn.disabled = false;
        }
    }
    
    // --- LÓGICA DO HISTÓRICO ---
    
    /**
     * @functionality 203
     * @category 2xx: Banco de Dados e Persistência
     * @name Gerenciamento de Histórico de Mensagens com Armazenamento Auto-Incrementado e Índices
     * @description Adiciona itens com timestamp.
     */
    function saveMessageToHistory(messageData) {
        if (!db) return;
        const transaction = db.transaction(['history'], 'readwrite');
        const store = transaction.objectStore('history');
        store.put(messageData);
    }

    /**
     * @functionality 203
     * @category 2xx: Banco de Dados e Persistência
     * @name Gerenciamento de Histórico de Mensagens com Armazenamento Auto-Incrementado e Índices
     * @description Renderiza lista expansível, suporta copy/delete/clear.
     * @functionality 402
     * @name Renderização Responsiva de Histórico com Expansão Colapsível e Ações Inline
     * @description Lista itens com botões copy/delete/expand, usando transições CSS para conteúdo oculto.
     */

async function renderHistory(cnpjFilter = '', startDateFilter = '', endDateFilter = '') {
    const container = document.getElementById('historyListContainer');
    container.innerHTML = '<p class="text-gray-500 text-center">Carregando histórico...</p>';
    if (!db) {
        container.innerHTML = '<p class="text-red-500 text-center">Banco de dados não disponível.</p>';
        return;
    }

    const transaction = db.transaction(['history'], 'readonly');
    const store = transaction.objectStore('history');
    const allRecords = await new Promise((resolve, reject) => {
        const request = store.getAll();
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
    });

    // --- LÓGICA DE FILTRAGEM (NOVO) ---
    let filteredRecords = allRecords;

    // Filtro por CNPJ/CPF
    if (cnpjFilter) {
        const cleanedCnpjFilter = cnpjFilter.replace(/\D/g, '');
        filteredRecords = filteredRecords.filter(item => {
            const cleanedItemCnpj = item.cnpj.replace(/\D/g, '');
            return cleanedItemCnpj.includes(cleanedCnpjFilter);
        });
    }

    // Filtro por Data Inicial
    if (startDateFilter) {
        const parts = startDateFilter.split('-'); // Corrige o bug do fuso horário (YYYY-MM-DD)
        const startDate = new Date(parts[0], parts[1] - 1, parts[2]); // Cria a data em fuso local
        startDate.setHours(0, 0, 0, 0); // Considera o início do dia
        filteredRecords = filteredRecords.filter(item => new Date(item.timestamp) >= startDate);
    }

    // Filtro por Data Final
    if (endDateFilter) {
        const parts = endDateFilter.split('-'); // Corrige o bug do fuso horário (YYYY-MM-DD)
        const endDate = new Date(parts[0], parts[1] - 1, parts[2]); // Cria a data em fuso local
        endDate.setHours(23, 59, 59, 999); // Considera o fim do dia
        filteredRecords = filteredRecords.filter(item => new Date(item.timestamp) <= endDate);
    }

    // --- FIM DA LÓGICA DE FILTRAGEM ---


    if (filteredRecords.length === 0) {
        container.innerHTML = '<p class="text-gray-500 text-center">Nenhum registro encontrado para os filtros aplicados.</p>';
        return;
    }

    container.innerHTML = '';
    // Renderiza os registros JÁ FILTRADOS
    filteredRecords.reverse().forEach(item => {
        const date = new Date(item.timestamp);
        const formattedDate = date.toLocaleString('pt-BR');
        const element = document.createElement('div');
        element.className = 'border rounded-lg bg-white shadow-sm overflow-hidden';
        element.innerHTML = `
            <div class="p-3 flex justify-between items-center bg-gray-50 border-b">
                <div class="flex-grow">
                    <p class="font-bold text-blue-700">${escapeHtml(item.companyName)}</p>
                    <p class="text-sm text-gray-600">${escapeHtml(item.cnpj)}</p>
                    <p class="text-xs text-gray-400 mt-1">Gerado em: ${formattedDate}</p>
                </div>
                <div class="flex items-center space-x-2 ml-2">
                    <button data-id="${item.id}" class="delete-history-btn text-red-500 hover:text-red-700 font-bold p-1 text-lg leading-none">&times;</button>
                    <button data-message="${encodeURIComponent(item.message)}" class="copy-history-btn bg-gray-200 text-gray-700 font-semibold py-1 px-3 rounded-lg hover:bg-gray-300 transition text-xs">Copiar</button>
                    <button class="expand-history-btn text-blue-600 font-semibold text-xs py-1 px-3">Expandir</button>
                </div>
            </div>
            <div class="history-message-content" style="max-height: 0; transition: max-height 0.3s ease-out;">
                <pre class="p-4 text-xs text-gray-800 whitespace-pre-wrap font-sans">${escapeHtml(item.message)}</pre>
            </div>
        `;
        container.appendChild(element);
    });
    }

    /**
     * @functionality 211
     * @category 2xx: Banco de Dados e Persistência
     * @name Limpeza Total de Histórico com Confirmação e Reset de Container
     * @description Deleta todos itens do store 'history' e limpa UI.
     */
    function clearHistory() {
        if (!confirm('Tem certeza que deseja apagar TODO o histórico de mensagens? Esta ação não pode ser desfeita.')) {
            return;
        }
        if (!db) return;
        const transaction = db.transaction(['history'], 'readwrite');
        const store = transaction.objectStore('history');
        const request = store.clear();
        request.onsuccess = () => {
            showToast('Histórico limpo com sucesso.', 'success');
            renderHistory();
        };
        request.onerror = () => {
            showToast('Erro ao limpar o histórico.', 'error');
        };
    }

    /**
     * @functionality 210
     * @category 2xx: Banco de Dados e Persistência
     * @name Deleção de Item de Histórico com Confirmação e Atualização de Lista
     * @description Remove por ID via transaction e re-renderiza lista.
     */
    function deleteHistoryItem(id) {
        if (!db) return;
        const transaction = db.transaction(['history'], 'readwrite');
        const store = transaction.objectStore('history');
        const request = store.delete(id);
        request.onsuccess = () => {
            showToast('Item removido do histórico.', 'success');
            renderHistory();
        };
         request.onerror = () => {
            showToast('Erro ao remover item.', 'error');
        };
    }

    // ---XX LÓGICA DE CONTATOS PESSOAIS XX---

    /**
     * @functionality 212
     * @category 2xx: Banco de Dados e Persistência
     * @name Renderização da Lista de Contatos Pessoais no Modal de DB
     * @description Lê o store 'contacts' e popula a lista no dbModal com botões de exclusão.
     */
    async function renderContactsList() {
        if (!db) return;
        contactsListContainer.innerHTML = '<p class="text-gray-500 text-center">Carregando...</p>';

        const transaction = db.transaction(['contacts'], 'readonly');
        const store = transaction.objectStore('contacts');
        const allContacts = await new Promise((resolve, reject) => {
            store.getAll().onsuccess = e => resolve(e.target.result);
            store.getAll().onerror = e => reject(e.target.error);
        });

        if (allContacts.length === 0) {
            contactsListContainer.innerHTML = '<p class="text-sm text-gray-500 text-center">Nenhum contato cadastrado.</p>';
            return;
        }

        contactsListContainer.innerHTML = '';
        allContacts.forEach(contact => {
            const div = document.createElement('div');
            div.className = 'flex justify-between items-center bg-white p-2 rounded border text-sm';
            div.innerHTML = `
                <div>
                    <p class="font-semibold text-gray-800">${escapeHtml(contact.name)}</p>
                    <p class="text-xs text-gray-600">${escapeHtml(contact.role)} (${escapeHtml(contact.phone)})</p>
                </div>
                <button data-id="${contact.id}" class="delete-contact-btn text-red-500 hover:text-red-700 font-bold p-1 text-lg leading-none">&times;</button>
            `;
            contactsListContainer.appendChild(div);
        });
    }

    /**
     * @functionality 213
     * @category 2xx: Banco de Dados e Persistência
     * @name Adicionar Contato Pessoal
     * @description Salva um novo contato no store 'contacts' a partir do formulário do modal.
     */
    function addContact() {
        const name = modalcontactNameInput.value.trim();
        const role = modalcontactRoleInput.value.trim();
        let phone = contactPhoneInput.value.trim().replace(/\D/g, '');

        if (!name || !phone) {
            showToast('Nome e WhatsApp são obrigatórios.', 'error');
            return;
        }

        if (phone.length <= 11) { // Ex: 719... ou 119...
             showToast('Telefone inválido. Inclua o código do país (55).', 'error');
             return;
        }

        const transaction = db.transaction(['contacts'], 'readwrite');
        const store = transaction.objectStore('contacts');
        store.put({ name, role, phone });

        transaction.oncomplete = () => {
            showToast('Contato adicionado!', 'success');
            modalcontactNameInput.value = '';
            modalcontactRoleInput.value = '';
            contactPhoneInput.value = '';
            renderContactsList();
        };
        transaction.onerror = () => showToast('Erro ao salvar contato.', 'error');
    }

    /**
     * @functionality 214
     * @category 2xx: Banco de Dados e Persistência
     * @name Deletar Contato Pessoal
     * @description Remove um contato do store 'contacts' por ID.
     */
    function deleteContact(id) {
        if (!db || !id) return;
        if (!confirm('Tem certeza que deseja remover este contato?')) return;
        
        const transaction = db.transaction(['contacts'], 'readwrite');
        const store = transaction.objectStore('contacts');
        store.delete(id);

        transaction.oncomplete = () => {
            showToast('Contato removido.', 'success');
            renderContactsList();
        };
        transaction.onerror = () => showToast('Erro ao remover contato.', 'error');
    }

    /**
     * @functionality 417
     * @category 4xx: UI/UX e Interações
     * @name Exportar CSV de Contatos Pessoais
     * @description Gera e baixa um arquivo CSV a partir do store 'contacts'.
     */
    async function exportContactsCsv() {
        if (!db) return;
        const transaction = db.transaction(['contacts'], 'readonly');
        const store = transaction.objectStore('contacts');
        const allContacts = await new Promise((resolve, reject) => {
            store.getAll().onsuccess = e => resolve(e.target.result);
            store.getAll().onerror = e => reject(e.target.error);
        });

        let csvContent = "Nome;;Cargo;;Telefone\n";
        allContacts.forEach(c => {
            csvContent += `${c.name};;${c.role};;${c.phone}\n`;
        });

        const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'contatos_pessoais_whatsapp.csv';
        a.click();
        URL.revokeObjectURL(url);
        showToast('CSV de Contatos exportado!', 'success');
    }

    /**
     * @functionality 314
     * @category 3xx: Geração de Mensagens e Formulários
     * @name Abrir Modal de Envio WhatsApp
     * @description Popula o wppModal com contatos do store 'contacts'.
     */
    async function openWppModal() {
        if (!db) {
            showToast('Banco de dados não disponível.', 'error');
            return;
        }
        const message = resultText.value;
        if (!message) {
            showToast('Gere uma mensagem antes de enviar.', 'error');
            return;
        }

        wppContactListContainer.innerHTML = '<p class="text-gray-500 text-center">Carregando contatos...</p>';
        const transaction = db.transaction(['contacts'], 'readonly');
        const store = transaction.objectStore('contacts');
        const allContacts = await new Promise((resolve, reject) => {
            store.getAll().onsuccess = e => resolve(e.target.result);
            store.getAll().onerror = e => reject(e.target.error);
        });

        if (allContacts.length === 0) {
            wppContactListContainer.innerHTML = '<p class="text-center text-red-500">Nenhum contato pessoal cadastrado. Adicione contatos no menu "Gerenciar Base de Dados".</p>';
        } else {
            wppContactListContainer.innerHTML = '';
            allContacts.forEach(contact => {
                const button = document.createElement('button');
                button.className = 'w-full text-left p-3 bg-gray-50 hover:bg-blue-100 rounded-lg transition';
                button.dataset.phone = contact.phone;
                button.innerHTML = `
                    <p class="font-semibold text-blue-700">${escapeHtml(contact.name)}</p>
                    <p class="text-sm text-gray-600">${escapeHtml(contact.role)}</p>
                `;
                wppContactListContainer.appendChild(button);
            });
        }
        wppModal.classList.remove('hidden');
    }

    /**
     * @functionality 315
     * @category 3xx: Geração de Mensagens e Formulários
     * @name Handler de Clique para Envio de WhatsApp
     * @description Pega o telefone do data-attribute e abre o link wa.me.
     */
    function handleWppContactClick(event) {
        const targetButton = event.target.closest('button');
        if (!targetButton || !targetButton.dataset.phone) return;

        const phone = targetButton.dataset.phone;
        const message = resultText.value;
        const encodedMessage = encodeURIComponent(message);
        const wppUrl = `https://wa.me/${phone}?text=${encodedMessage}`;
        
        window.open(wppUrl, '_blank');
        wppModal.classList.add('hidden');
    }

    // ---XX LÓGICA PRINCIPAL DA APLICAÇÃO XX---

    /**
     * @functionality 204
     * @category 2xx: Banco de Dados e Persistência
     * @name Parsing de CSV para Empresas com Delimitador ';;' e Codificação ISO-8859-1
     * @description Extrai CNPJ e nome de linhas CSV, ignora headers e linhas vazias.
     */
    const companyParser = (line) => {
        const parts = line.split(';;');
        if (parts.length >= 2) {
            const cnpj = parts[0].trim().replace(/\D/g, '');
            const razaoSocial = parts[1]?.trim();
            const dataCadastro = parts[2]?.trim() || '';
            const tipoCadastro = parts[3]?.trim() || '';

            if (cnpj && razaoSocial) 
                return { cnpj, razaoSocial, dataCadastro, tipoCadastro };
        }
        return null;
    }

    /**
     * @functionality 205
     * @category 2xx: Banco de Dados e Persistência
     * @name Parsing de CSV para Famílias com Mapeamento de ID e Descrição
     * @description Extrai ID e descrição de famílias de linhas CSV delimitadas por ';;'.
     */
    const familyParser = (line) => {
        const parts = line.split(';;');
        if (parts.length >= 3) {
            const id = parts[0]?.trim();
            const description = parts[2]?.trim();
            if(id && description) return { id, description };
        }
        return null;
    }

    /**
     * @functionality 205.5
     * @category 2xx: Banco de Dados e Persistência
     * @name Parsing de CSV para Contatos Pessoais
     * @description Extrai nome, cargo e telefone de linhas CSV delimitadas por ';;'.
     */
    const contactsParser = (line) => {
        const parts = line.split(';;');
        if (parts.length >= 3) {
            const name = parts[0]?.trim();
            const role = parts[1]?.trim();
            const phone = parts[2]?.trim().replace(/\D/g, ''); // Limpa o telefone
            if(name && phone) return { name, role, phone };
        }
        return null;
    }

    /**
     * @functionality 302
     * @category 3xx: Geração de Mensagens e Formulários
     * @name Busca e Preenchimento Automático de Dados de Empresa via IndexedDB
     * @description Consulta store 'companies' por CNPJ formatado, popula nome da empresa e exibe status de validação.
     */
    function searchCnpj(doc) {
        companyNameResults.innerHTML = ''; //limpa lista de sugestões
        if (!encryptionKey) {
            showToast('Por favor, faça login para usar a base de dados.', 'error');
            return;
        }
        const cleanedDoc = doc.replace(/\D/g, '');
        if ((cleanedDoc.length !== 11 && cleanedDoc.length !== 14) || !db) {
            companyNameInputForDb.value = '';
            cnpjStatusSpan.textContent = '';
            return;
        }
        
        cnpjStatusSpan.textContent = 'Buscando...';
        cnpjStatusSpan.className = 'text-gray-500';

        const transaction = db.transaction(["companies"], "readonly");
        const objectStore = transaction.objectStore("companies");
        const request = objectStore.get(cleanedDoc);

        request.onsuccess = function(event) {
            if (request.result) {
                companyNameInputForDb.value = request.result.razaoSocial;
                registrationDateInput.value = request.result.dataCadastro || '--'; 

                // 2. Preenche o tipo de cadastro (campo selecionável)
                if (request.result.tipoCadastro) {
                    const tipo = request.result.tipoCadastro.trim().toUpperCase();
                    if (tipo === 'CRC') {
                        registrationTypeInput.value = 'CRC';
                    } else if (tipo === 'CRS') {
                        registrationTypeInput.value = 'CRS';
                    } else if (tipo === 'CANDIDATO') {
                        registrationTypeInput.value = 'Candidato';
                    } else {
                        registrationTypeInput.value = 'CRC'; // Padrão se não reconhecer
                    }
                } else {
                    registrationTypeInput.value = 'CRC'; // Padrão se não existir no DB
                }
                cnpjStatusSpan.textContent = 'Encontrado';
                cnpjStatusSpan.className = 'text-green-600';
            } else {
                companyNameInputForDb.value = '';
                registrationDateInput.value = '--'; 
                registrationTypeInput.value = 'CRC'; 
                cnpjStatusSpan.textContent = 'Não encontrado';
                cnpjStatusSpan.className = 'text-red-600';
            }
        };
         request.onerror = function(event) {
             cnpjStatusSpan.textContent = 'Erro';
             cnpjStatusSpan.className = 'text-red-600';
             registrationDateInput.value = '--'; 
             registrationTypeInput.value = 'CRC'; 
         }
    }

    /**
     * @functionality 302.5
     * @category 3xx: Geração de Mensagens e Formulários
     * @name Sistema de Autocomplete para Busca de Empresas por Razão Social
     * @description Busca fuzzy (contains) em companies store via cursor, limita a 10 resultados.
     */
    function searchCompanyByName(searchTerm) {
        if (!encryptionKey) return; // Não mostra toast, para não poluir
        companyNameResults.innerHTML = '';
        if (searchTerm.length < 5 || !db) return; // Limite de 6 caracteres

        const transaction = db.transaction(['companies'], 'readonly');
        const store = transaction.objectStore('companies');
        const request = store.openCursor();
        const results = [];
        const lowerCaseSearchTerm = searchTerm.toLowerCase();

        request.onsuccess = function(event) {
            const cursor = event.target.result;
            if (cursor) {
                if (cursor.value.razaoSocial.toLowerCase().includes(lowerCaseSearchTerm)) {
                    results.push(cursor.value);
                }
                if (results.length < 10) { // Limita a 10 resultados
                    cursor.continue();
                } else {
                     displayCompanyNameResults(results); // Atingiu o limite
                }
            } else {
                displayCompanyNameResults(results); // Fim do cursor
            }
        };
    }

    /**
     * @functionality 302.6
     * @category 3xx: Geração de Mensagens e Formulários
     * @name Renderização de Resultados de Autocomplete de Empresa
     * @description Preenche div com resultados clicáveis, armazenando dados em data-attributes.
     */
    function displayCompanyNameResults(results) {
        companyNameResults.innerHTML = '';
        results.forEach(company => {
            const div = document.createElement('div');
            // Estilização idêntica à de famílias (via CSS em index/style.css)
            div.className = 'p-3 hover:bg-gray-100 cursor-pointer text-sm'; 
            div.textContent = company.razaoSocial;
            div.dataset.cnpj = company.cnpj;
            div.dataset.razaoSocial = company.razaoSocial;
            div.dataset.dataCadastro = company.dataCadastro || ''; 
            div.dataset.tipoCadastro = company.tipoCadastro || ''; 
            companyNameResults.appendChild(div);
        });
    }
    
    /**
     * @functionality 309
     * @category 3xx: Geração de Mensagens e Formulários
     * @name Mapeamento de Documentos por Categoria em Objeto Constante
     * @description Define array docsByCat com listas de docs por aba (ex: Habilitação Jurídica).
     */
    const docsByCat = {
        "Dados do Fornecedor": ["Documento de Identificação"],
        "Habilitação Jurídica": ["Contrato Social", "Estatuto Social", "Ata", "Sócio", "Dirigente"],
        "Família": [],
        "Qualificação Técnica": [],
        "Regularidade Fiscal e Trabalhista": ["Cartão CNPJ", "Cadastro de Contribuinte Estadual", "Cadastro de Contribuinte Municipal", "Regularidade Fazenda Federal e a Dívida Ativa e INSS", "Regularidade com a Fazenda Estadual", "Regularidade Faz. Estadual (Licitação)", "Regularidade com a Fazenda Municipal", "Regularidade com o FGTS - CEF", "Certidão de Débitos Trabalhistas"],
        "Qualificação Econômico-Financeira": ["Concordata e Falência", "Balanço 01", "Balanço 02"],
        "Formulários e Declarações": ["Declaração do Empregador", "Declaração de Superveniência", "Declaração de Enquadramento", "Declaração de Desenquadramento", "Procuração", "Comprovante de Residência", "Termo de Concordância e Veracidade"]
    };

    
    const statusRadios = document.querySelectorAll('input[name="status"]');
    const rejectedDocsSection = document.getElementById('rejected-docs-section');
    const generateBtn = document.getElementById('generateBtn');
    const resultSection = document.getElementById('result-section');
    const resultText = document.getElementById('resultText');
    const copyBtn = document.getElementById('copyBtn');
    const addDocBtn = document.getElementById('addDocBtn');
    const rejectedDocsListContainer = document.getElementById('rejected-docs-list');
    const companyNameInput = document.getElementById('companyName');
    const analysisDateInput = document.getElementById('analysisDate');
    const registrationTypeInput = document.getElementById('registrationType');
    const registrationDateInput = document.getElementById('registrationDate');
    const docCategoryInput = document.getElementById('docCategory');
    const docNameSelect = document.getElementById('docName');
    const customDocNameWrapper = document.getElementById('customDocNameWrapper');
    const customDocNameInput = document.getElementById('customDocName');
    const socioNameWrapper = document.getElementById('socioNameWrapper');
    const socioNameInput = document.getElementById('socioName');
    const rejectionReasonInput = document.getElementById('rejectionReason');
    const docNameWrapper = document.getElementById('docNameWrapper');
    const familyAutocompleteWrapper = document.getElementById('familyAutocompleteWrapper');
    const familySearchInput = document.getElementById('familySearchInput');
    const familyResults = document.getElementById('familyResults');
    const contactMadeCheckbox = document.getElementById('contactMade');
    const contactDetailsWrapper = document.getElementById('contactDetailsWrapper');
    const contactNameInput = document.getElementById('contactName');
    const contactRoleInput = document.getElementById('contactRole');
    let rejectedDocs = [];
    let selectedFamilyId = null;

    /**
     * @functionality 312
     * @category 3xx: Geração de Mensagens e Formulários
     * @name Reset de Campos de Formulário Após Busca de CNPJ
     * @description Limpa nome, contato, docs e rejected list ao digitar novo CNPJ.
     */
    function resetFormFields() {
        document.getElementById('statusDeferida').checked = true;
        registrationTypeInput.value = 'CRC';
        registrationDateInput.value = '';
        const today = new Date().toISOString().split('T')[0];
        analysisDateInput.value = today;
        rejectedDocs = [];
        renderRejectedDocs();
        toggleRejectedDocsSection();
        resultSection.classList.add('hidden');
        resultText.value = '';
        contactMadeCheckbox.checked = false;
        contactDetailsWrapper.classList.add('hidden');
        contactNameInput.value = '';
        contactRoleInput.value = 'Sócio(a)';
    }

    /**
     * @functionality 305
     * @category 3xx: Geração de Mensagens e Formulários
     * @name Preenchimento Dinâmico de Selects de Documentos por Categoria
     * @description Mapeia docsByCat para opções de select, com fallback para 'outro' e custom input.
     */
    const populateDocNames = () => {
        const selectedCategory = docCategoryInput.value;
        
        familyAutocompleteWrapper.classList.add('hidden');
        docNameWrapper.classList.remove('hidden');
        customDocNameWrapper.classList.add('hidden');
        socioNameWrapper.classList.add('hidden');
        familySearchInput.value = '';
        selectedFamilyId = null;

        if (selectedCategory === 'Família') {
            docNameWrapper.classList.add('hidden');
            familyAutocompleteWrapper.classList.remove('hidden');
            return;
        }

        const docs = docsByCat[selectedCategory] || [];
        docNameSelect.innerHTML = ''; 

        docs.forEach(doc => {
            const option = document.createElement('option');
            option.value = doc;
            option.textContent = doc;
            docNameSelect.appendChild(option);
        });

        const otherOption = document.createElement('option');
        otherOption.value = 'outro';
        otherOption.textContent = 'Outro...';
        docNameSelect.appendChild(otherOption);
        
        if (selectedCategory === 'Qualificação Técnica') {
            docNameSelect.value = 'outro';
        }
        handleDocNameChange();
    };

    /**
     * @functionality 310
     * @category 3xx: Geração de Mensagens e Formulários
     * @name Tratamento de Input Customizado para Documentos 'Outro' ou 'Sócio'
     * @description Mostra/oculta inputs para nome custom ou sócio baseado em select.
     */
    function handleDocNameChange() {
        const selectedDoc = docNameSelect.value;
        customDocNameWrapper.classList.add('hidden');
        socioNameWrapper.classList.add('hidden');

        if (selectedDoc === 'outro') {
            customDocNameWrapper.classList.remove('hidden');
            customDocNameInput.focus();
        } else if (selectedDoc === 'Sócio') {
            socioNameWrapper.classList.remove('hidden');
            socioNameInput.focus();
        }
    }

    /**
     * @functionality 303
     * @category 3xx: Geração de Mensagens e Formulários
     * @name Manipulação Dinâmica de Seção de Documentos Indeferidos
     * @description Toggle visibilidade por status.
     * @functionality 306
     * @name Toggle Condicional de Campos de Análise por Status de Cadastro
     * @description Desabilita/enable campos (data, tipo) para status 'Pendente'.
     */
    const toggleRejectedDocsSection = () => {
        const selectedStatus = document.querySelector('input[name="status"]:checked').value;
        const analysisFields = document.getElementById('company-data').querySelectorAll('input[type="date"], select');
        
        if (selectedStatus === 'Deferida Parcial' || selectedStatus === 'Indeferida') {
            rejectedDocsSection.classList.remove('hidden');
             analysisFields.forEach(field => field.disabled = false);
        } else {
            rejectedDocsSection.classList.add('hidden');
        }

        if (selectedStatus === 'Pendente de Envio' || selectedStatus === 'Pendente do Termo') {
            analysisFields.forEach(field => {
                field.disabled = true;
                field.classList.add('bg-gray-100');
            });
             analysisDateInput.disabled = true;
             analysisDateInput.classList.add('bg-gray-100');
        } else {
             analysisFields.forEach(field => {
                field.disabled = false;
                field.classList.remove('bg-gray-100');
             });
             analysisDateInput.disabled = false;
             analysisDateInput.classList.remove('bg-gray-100');
        }
    };

    /**
     * @functionality 307
     * @category 3xx: Geração de Mensagens e Formulários
     * @name Formatação de Data de Análise para DD/MM/AAAA
     * @description Converte ISO date string para formato brasileiro.
     */
    const formatDate = (dateString) => {
        if (!dateString) return '';
        const [year, month, day] = dateString.split('-');
        return `${day}/${month}/${year}`;
    };
    
    /**
     * @functionality 405
     * @category 4xx: UI/UX e Interações
     * @name Renderização de Lista de Documentos Indeferidos com Remoção Inline
     * @description Gera HTML dinâmico para itens de rejectedDocs, com botões de remoção por índice.
     */
    const renderRejectedDocs = () => {
        rejectedDocsListContainer.innerHTML = '';
        if (rejectedDocs.length === 0) return;

        const heading = document.createElement('h3');
        heading.className = 'text-md font-semibold text-gray-600';
        heading.textContent = 'Documentos Adicionados:';
        rejectedDocsListContainer.appendChild(heading);

        rejectedDocs.forEach((doc, index) => {
            const docElement = document.createElement('div');
            docElement.className = 'flex justify-between items-center bg-white p-3 rounded-lg border';
            
            let docDisplayName = doc.name;
            if (doc.name === 'Sócio' && doc.socioName) {
                docDisplayName += `: ${doc.socioName}`;
            }
            
            docElement.innerHTML = `
                <div class="text-sm">
                    <p class="font-bold text-blue-700">${escapeHtml(doc.category)}</p>
                    <p class="text-gray-800">${escapeHtml(docDisplayName)}</p>
                    <p class="text-gray-500 italic">Motivo: ${escapeHtml(doc.reason)}</p>
                </div>
                <button data-index="${index}" class="remove-doc-btn text-red-500 hover:text-red-700 font-bold p-1">&times;</button>
            `;
            rejectedDocsListContainer.appendChild(docElement);
        });
    };
    
    /**
     * @functionality 303
     * @category 3xx: Geração de Mensagens e Formulários
     * @name Manipulação Dinâmica de Seção de Documentos Indeferidos
     * @description Adiciona/remove itens em array e atualiza a UI.
     */
    const addRejectedDoc = () => {
        const category = docCategoryInput.value;
        let name;
        const reason = rejectionReasonInput.value.trim();
        let socioName = null;
        
        if (category === 'Família') {
            name = familySearchInput.value.trim();
            if (!selectedFamilyId || name === '') {
                alert('Por favor, selecione uma família da lista de sugestões.');
                return;
            }
        } else {
            name = docNameSelect.value;
            if (name === 'outro') {
                name = customDocNameInput.value.trim();
            } else if (name === 'Sócio') {
                socioName = socioNameInput.value.trim();
                if (!socioName) {
                    alert('Por favor, preencha o nome do sócio.');
                    return;
                }
            }
        }

        if (!name || !reason) {
            alert('Por favor, preencha o nome do documento e o motivo.');
            return;
        }

        rejectedDocs.push({ category, name, reason, socioName });
        renderRejectedDocs();
        
        showToast('Documento adicionado!', 'success');
        rejectionReasonInput.value = '';
        customDocNameInput.value = '';
        socioNameInput.value = '';
        populateDocNames();
        rejectionReasonInput.focus();
    };

    const removeRejectedDoc = (index) => {
        rejectedDocs.splice(index, 1);
        renderRejectedDocs();
    };
    
    /**
     * @functionality 304
     * @category 3xx: Geração de Mensagens e Formulários
     * @name Sistema de Autocomplete para Busca de Famílias na DB com Cursor Pagination
     * @description Busca fuzzy em families store via cursor, limita a 10 resultados, seleciona via click.
     */
    function searchFamilies(searchTerm) {
        if (!encryptionKey) {
            showToast('Por favor, faça login para usar a base de dados.', 'error');
            return;
        }
        familyResults.innerHTML = '';
        if (!searchTerm || !db) return;

        const transaction = db.transaction(['families'], 'readonly');
        const store = transaction.objectStore('families');
        const request = store.openCursor(); 
        const results = [];

        request.onsuccess = function(event) {
            const cursor = event.target.result;
            if (cursor) {
                if (cursor.value.description.toLowerCase().includes(searchTerm.toLowerCase())) {
                    results.push(cursor.value);
                }
                cursor.continue();
            } else {
                displayFamilyResults(results.slice(0, 10));
            }
        };
    }

    function displayFamilyResults(results) {
        familyResults.innerHTML = '';
        results.forEach(family => {
            const div = document.createElement('div');
            div.textContent = family.description;
            div.dataset.id = family.id;
            div.dataset.description = family.description;
            familyResults.appendChild(div);
        });
    }
    
    /**
     * @functionality 300
     * @category 3xx: Geração de Mensagens e Formulários
     * @name Geração de Mensagens Personalizadas com Template Switch por Status
     * @description Monta strings Markdown-like baseadas em status, com agrupamento de docs e footer. Salva em histórico.
     * @functionality 313
     * @name Validações de Formulário Antes de Geração com Alerts
     * @description Checa campos obrigatórios.
     */
    const generateMessage = () => {
        if (!encryptionKey) {
            showToast('Por favor, faça login para usar o aplicativo.', 'error');
            return;
        }
        const companyName = companyNameInput.value.trim();
        const cnpj = cnpjInputForDb.value.trim();
        const analysisDate = formatDate(analysisDateInput.value);
        const registrationType = registrationTypeInput.value;
        const status = document.querySelector('input[name="status"]:checked').value;
        const contactMade = contactMadeCheckbox.checked;
        const contactName = contactNameInput.value.trim();
        const contactRole = contactRoleInput.value;

        if (!companyName || !cnpj) {
            alert('Por favor, preencha o CNPJ/CPF e o Nome/Razão Social.');
            return;
        }
        
        if (status !== 'Pendente de Envio' && status !== 'Pendente do Termo' && !analysisDate) {
             alert('Por favor, preencha a data da análise.');
             return;
        }
        
        if (contactMade && (!contactName || !contactRole)) {
            alert('Por favor, preencha o Nome do Contato e o Cargo.');
            return;
        }

        const legalFooter = `Importante salientar que as documentações necessárias para registro no Cadastro de Fornecedores do estado da Bahia – CAF obedecem ao quanto previsto nos art. 62 a 70 e 87 e 88, da Lei Federal nº 14.133/2021 c/c o art. 76 da Lei Estadual nº 14.634/2023.`;
        const defaultEmailFooter = `O fornecedor é notificado automaticamente por e-mail.`;
        const contactMadeFooter = `O fornecedor é notificado automaticamente por e-mail. Contudo, em contato com o(a) Sr.(a) *${contactName}*, *${contactRole}* da Empresa, foram esclarecidos os motivos do indeferimento, tendo sido informado que estão sendo adotadas as providências necessárias para correção e que será sinalizado quando houver nova solicitação.`;
        let message = '';
        const docIdentifier = cnpj.replace(/\D/g, '').length > 11 ? 'CNPJ sob o nº' : 'CPF sob o nº';

        switch (status) {
            case 'Deferida':
                message = `A solicitação do fornecedor *${companyName}*, inscrito no ${docIdentifier} *${cnpj}*, foi analisada e *${status}* em *${analysisDate}* para o tipo de cadastro *${registrationType}*.\n\n${legalFooter}\n\n${defaultEmailFooter}`;
                break;
            case 'Deferida Parcial':
            case 'Indeferida':
                if (rejectedDocs.length === 0) {
                     alert(`Para o status "${status}", é necessário adicionar pelo menos um documento indeferido.`);
                     return;
                }
                let docsText = 'Documentos analisados e Indeferidos:\n\n';
                const groupedByCategory = rejectedDocs.reduce((acc, doc) => {
                    (acc[doc.category] = acc[doc.category] || []).push(doc);
                    return acc;
                }, {});
                for (const category in groupedByCategory) {
                    docsText += `*${category}*\n\n`;
                    groupedByCategory[category].forEach(doc => {
                        let docTitle;
                        if (doc.name === 'Sócio' && doc.socioName) {
                            docTitle = `*SÓCIO: ${doc.socioName.toUpperCase()}*`;
                        } else {
                            docTitle = `*${doc.name.toUpperCase()}*`;
                        }
                        docsText += `${docTitle}\n`;
                        docsText += `*Motivo*: _${doc.reason}_\n\n`;
                    });
                }
                const finalEmailFooter = contactMade ? contactMadeFooter : defaultEmailFooter;
                message = `A solicitação do fornecedor *${companyName}*, inscrito no ${docIdentifier} *${cnpj}*, foi analisada e *${status}* em *${analysisDate}* para o tipo de cadastro *${registrationType}*, conforme análise abaixo:\n\n${docsText}${legalFooter}\n\n${finalEmailFooter}`;
                break;
            case 'Pendente de Envio':
                message = `A solicitação do fornecedor *${companyName}*, inscrito no ${docIdentifier} *${cnpj}*, encontra-se *Pendente de Envio*.\n\nÉ necessário que o fornecedor acesse o CAF Digital, atualize os dados necessários e realize o envio da solicitação para análise pela Comissão de Inscrição e Registro Cadastral.`;
                break;
            case 'Pendente do Termo':
                 message = `A solicitação enviada pelo fornecedor *${companyName}*, inscrito no ${docIdentifier} *${cnpj}*, encontra-se *Pendente do envio do Termo de Concordância e Veracidade*.\n\nO fornecedor poderá realizar o envio do referido Termo por meio do *CAF Digital*, assinando-o eletronicamente com Certificado ICP-Brasil (por exemplo, utilizando o Assinador gov.br), ou optar pela entrega presencial, conforme orientações contidas no próprio Termo.`;
                 break;
        }
        
        resultText.value = message;
        resultSection.classList.remove('hidden');
        resultText.style.height = 'auto';
        resultText.style.height = (resultText.scrollHeight + 10) + 'px';
        resultText.scrollIntoView({ behavior: 'smooth', block: 'end' });

        const messageData = {
            cnpj: cnpj,
            companyName: companyName,
            message: message,
            timestamp: new Date().toISOString()
        };
        saveMessageToHistory(messageData);
        showToast('Mensagem gerada e salva no histórico!', 'success');
    };

    /**
     * @functionality 406
     * @category 4xx: UI/UX e Interações
     * @name Cópia para Clipboard com Fallback e Toast de Feedback
     * @description Usa Navigator Clipboard API para copiar texto de mensagem ou histórico.
     */
    const copyToClipboard = (text) => {
        if (!text) return;
        
        navigator.clipboard.writeText(text).then(() => {
            showToast('Texto copiado com sucesso!', 'success');
        }).catch(err => {
            console.error('Falha ao copiar texto: ', err);
            showToast('Erro ao copiar texto.', 'error');
        });
    };

    // --- EVENT LISTENERS ---

    // Modais
    /**
     * @functionality 404
     * @category 4xx: UI/UX e Interações
     * @name Binding de Eventos para Modais com Fechamento por Clique Externo
     * @description Adiciona listeners para abrir/fechar modais (DB, histórico, export, senha) via classes Tailwind.
     */
    openDbModalBtn.addEventListener('click', async () => {
        // Carrega o valor salvo no select ao abrir o modal
        try {
            const savedPeriod = await getBackupReminderPeriod();
            // Garante que o elemento existe antes de tentar definir o valor
            if (backupReminderPeriodSelect) { 
                backupReminderPeriodSelect.value = savedPeriod;
            }
        } catch (e) {
            if (backupReminderPeriodSelect) {
                backupReminderPeriodSelect.value = 86400000; // Padrão
            }
        }
        dbModal.classList.remove('hidden');
    });

    closeDbModalBtn.addEventListener('click', () => dbModal.classList.add('hidden'));
    dbModal.addEventListener('click', (e) => { if (e.target.id === 'dbModal') dbModal.classList.add('hidden'); });
    
    openHistoryModalBtn.addEventListener('click', () => {
    historyModal.classList.remove('hidden');
    // Limpa os campos de filtro e renderiza a lista completa ao abrir
    historySearchCnpj.value = '';
    historyStartDate.value = '';
    historyEndDate.value = '';
    renderHistory();
    });

    // Listener para o botão de filtrar
    filterHistoryBtn.addEventListener('click', () => {
    const cnpj = historySearchCnpj.value.trim();
    const startDate = historyStartDate.value;
    const endDate = historyEndDate.value;
    renderHistory(cnpj, startDate, endDate);
    });

    // Listener para limpar os filtros
    clearHistoryFilterBtn.addEventListener('click', () => {
    historySearchCnpj.value = '';
    historyStartDate.value = '';
    historyEndDate.value = '';
    renderHistory(); // Renderiza a lista completa novamente
    });

    // Ajusta o CNPJ no filtro de history
    historySearchCnpj.addEventListener('input', (e) => {
        let v = e.target.value.replace(/\D/g, ''); // Remove tudo que não é dígito
        
        if (v.length <= 11) { // Formato CPF
            v = v.replace(/(\d{3})(\d)/, '$1.$2');
            v = v.replace(/(\d{3})(\d)/, '$1.$2');
            v = v.replace(/(\d{3})(\d{1,2})$/, '$1-$2');
        } else { // Formato CNPJ
            v = v.replace(/^(\d{2})(\d)/, '$1.$2');
            v = v.replace(/^(\d{2})\.(\d{3})(\d)/, '$1.$2.$3');
            v = v.replace(/\.(\d{3})(\d)/, '.$1/$2');
            v = v.replace(/(\d{4})(\d)/, '$1-$2');
        }
        e.target.value = v;
    });

    closeHistoryModalBtn.addEventListener('click', () => historyModal.classList.add('hidden'));
    historyModal.addEventListener('click', (e) => { if (e.target.id === 'historyModal') historyModal.classList.add('hidden'); });

    document.getElementById('exportDbBtn').addEventListener('click', () => {
        updateAdminControlsState();
        exportModal.classList.remove('hidden');
    });
    cancelExportBtn.addEventListener('click', () => {
        exportModal.classList.add('hidden');
    });
    exportModal.addEventListener('click', (e) => {
        if (e.target.id === 'exportModal') {
            exportModal.classList.add('hidden');
        }
    });
    confirmExportBtn.addEventListener('click', () => {
        const options = {
            includeCompanies: document.getElementById('exportCompanies').checked,
            includeFamilies: document.getElementById('exportFamilies').checked,
            includeHistory: document.getElementById('exportHistory').checked,
            includeContacts: document.getElementById('exportContacts').checked
        };
        processExport(options);
        exportModal.classList.add('hidden');
    });

    // Banco de Dados e Histórico
    document.getElementById('loadCsvBtn').addEventListener('click', () => {
         const file = document.getElementById('csvFileInput').files[0]; // <<< LINHA CORRIGIDA
         loadCsvToDB(file, 'companies', dbStatus, companyParser);
    });
    document.getElementById('loadFamilyCsvBtn').addEventListener('click', () => {
         const file = document.getElementById('familyCsvFileInput').files[0]; // <<< LINHA CORRIGIDA
         loadCsvToDB(file, 'families', familyDbStatus, familyParser);
    });
    /**
     * @functionality 301
     * @category 3xx: Geração de Mensagens e Formulários
     * @name Validação e Formatação Automática de CNPJ/CPF com Máscara Dinâmica
     * @description Aplica máscaras regex baseadas no tamanho (11 para CPF, 14 para CNPJ) e busca na DB.
     */
    cnpjInputForDb.addEventListener('input', (e) => {
        e.target.value = formatDocument(e.target.value);
        resetFormFields(); 
        searchCnpj(e.target.value);
    });

    document.getElementById('importDbFile').addEventListener('change', importDatabase);
    document.getElementById('clearHistoryBtn').addEventListener('click', clearHistory);

    // Listener para buscar por nome ao digitar
    companyNameInputForDb.addEventListener('input', (e) => {
        const searchTerm = e.target.value;
        if (searchTerm.length === 0) {
            companyNameResults.innerHTML = ''; // Limpa se o campo estiver vazio
            cnpjStatusSpan.textContent = ''; // Limpa o status
        } else if (searchTerm.length >= 5) {
            cnpjStatusSpan.textContent = 'Buscando...'; // Indica busca
            cnpjStatusSpan.className = 'text-gray-500';
            searchCompanyByName(searchTerm);
        }
    });

    // Listener para preencher CNPJ ao clicar no resultado do nome
    companyNameResults.addEventListener('click', (e) => {
        if (e.target.tagName === 'DIV') {
            const cnpj = e.target.dataset.cnpj;
            const razaoSocial = e.target.dataset.razaoSocial;
            const dataCadastro = e.target.dataset.dataCadastro; 
            const tipoCadastro = e.target.dataset.tipoCadastro; 

        // Reseta o resto do formulário (status, data, docs)
        resetFormFields();

        // Preenche os campos
        companyNameInputForDb.value = razaoSocial;
        cnpjInputForDb.value = formatDocument(cnpj);
        registrationDateInput.value = dataCadastro || '--'; 

        // Lógica de mapeamento do Tipo de Cadastro (igual ao searchCnpj)
        if (tipoCadastro) {
            const tipo = tipoCadastro.trim().toUpperCase();
            if (tipo === 'CRC') {
                registrationTypeInput.value = 'CRC';
            } else if (tipo === 'CRS') {
                registrationTypeInput.value = 'CRS';
            } else if (tipo === 'CANDIDATO') {
                registrationTypeInput.value = 'Candidato';
            } else {
                registrationTypeInput.value = 'CRC'; // Padrão
            }
        } else {
            registrationTypeInput.value = 'CRC'; // Padrão
        }

            // Atualiza o status
            cnpjStatusSpan.textContent = 'Encontrado';
            cnpjStatusSpan.className = 'text-green-600';

            // Limpa os resultados
            companyNameResults.innerHTML = '';
            

        }
    });

    // Formulário principal
    statusRadios.forEach(radio => radio.addEventListener('change', toggleRejectedDocsSection));
    addDocBtn.addEventListener('click', addRejectedDoc);
    generateBtn.addEventListener('click', generateMessage);
    copyBtn.addEventListener('click', () => copyToClipboard(resultText.value));
    docCategoryInput.addEventListener('change', populateDocNames);
    docNameSelect.addEventListener('change', handleDocNameChange);
    /**
     * @functionality 311
     * @category 3xx: Geração de Mensagens e Formulários
     * @name Seleção de Família via Autocomplete com Dataset Attributes
     * @description Armazena ID e descrição em data-attributes para uso posterior.
     */
    familySearchInput.addEventListener('input', (e) => searchFamilies(e.target.value));
    familyResults.addEventListener('click', (e) => {
        if (e.target.tagName === 'DIV') {
            familySearchInput.value = e.target.textContent;
            selectedFamilyId = e.target.dataset.id;
            familyResults.innerHTML = '';
        }
    });

    rejectedDocsListContainer.addEventListener('click', function(e) {
        if (e.target.classList.contains('remove-doc-btn')) {
            const index = e.target.getAttribute('data-index');
            removeRejectedDoc(index);
        }
    });

    // --- LISTENERS DO LEMBRETE DE BACKUP E CONFIGURAÇÃO ---

    // Salva o período imediatamente ao ser alterado no modal de DB
    // Adiciona uma verificação para garantir que o elemento existe
    if (backupReminderPeriodSelect) {
        backupReminderPeriodSelect.addEventListener('change', async (e) => {
            try {
                await saveBackupReminderPeriod(Number(e.target.value));
                showToast('Frequência do lembrete atualizada!', 'success');
            } catch (error) {
                showToast('Erro ao salvar a frequência.', 'error');
            }
        });
    }

    // Ações do modal de lembrete (adiciona verificações)
    if (confirmBackupReminderBtn) {
        confirmBackupReminderBtn.addEventListener('click', async () => {
            const options = {
                includeCompanies: false,
                includeFamilies: false,
                includeHistory: true,
                includeContacts: true
            };
            
            // 1. Inicia a exportação (que já exibe um toast)
            await processExport(options); 
            
            // 2. Atualiza o timestamp do último backup
            await updateLastPersonalBackupTimestamp(Date.now());
            
            // 3. Fecha o modal
            backupReminderModal.classList.add('hidden');
        });
    }

    if (cancelBackupReminderBtn) {
        cancelBackupReminderBtn.addEventListener('click', () => {
            backupReminderModal.classList.add('hidden');
        });
    }

    if (closeBackupReminderBtn) {
        closeBackupReminderBtn.addEventListener('click', () => {
            backupReminderModal.classList.add('hidden');
        });
    }


    //  if (backupReminderModal) {
    //      backupReminderModal.addEventListener('click', (e) => {
    //        if (e.target.id === 'backupReminderModal') {
    //            backupReminderModal.classList.add('hidden');
    //        }
    //    });
    //}
    
    /**
     * @functionality 413
     * @category 4xx: UI/UX e Interações
     * @name Event Delegation para Ações no Container de Histórico
     * @description Um listener único para copy/delete/expand em itens dinâmicos.
     * @functionality 411
     * @name Expansão/Colapso de Conteúdo de Mensagem no Histórico com Transições
     * @description Alterna max-height via CSS para animação suave.
     */
    document.getElementById('historyListContainer').addEventListener('click', function(e) {
        const target = e.target;
        if (target.classList.contains('copy-history-btn')) {
            const message = decodeURIComponent(target.dataset.message);
            copyToClipboard(message);
        } else if (target.classList.contains('delete-history-btn')) {
            const id = parseInt(target.dataset.id, 10);
            deleteHistoryItem(id);
        } else if (target.classList.contains('expand-history-btn')) {
            const content = target.closest('.border').querySelector('.history-message-content');
            
        // Verifica se está recolhido (maxHeight é '0px', nulo ou vazio)
        if (!content.style.maxHeight || content.style.maxHeight === '0px') {
            // Se está recolhido, expande
            content.style.maxHeight = content.scrollHeight + "px";
            target.textContent = 'Recolher';
        } else {
            // Se está expandido, recolhe
            content.style.maxHeight = null;
            target.textContent = 'Expandir';
        }
        }
        });

    /**
     * @functionality 308
     * @category 3xx: Geração de Mensagens e Formulários
     * @name Validação de Contato com Fornecedor e Toggle de Wrapper
     * @description Mostra/oculta campos de nome/cargo se checkbox marcado.
     */
    contactMadeCheckbox.addEventListener('change', () => {
        contactDetailsWrapper.classList.toggle('hidden', !contactMadeCheckbox.checked);
    });

    // Event Listeners de Autenticação
    loginBtn.addEventListener('click', () => {
        passwordModal.classList.remove('hidden');
        masterPasswordInput.focus();
    });
    passwordForm.addEventListener('submit', handlePasswordSubmit);
    logoutBtn.addEventListener('click', handleLogout);

    // Listeners do Modal de WhatsApp
    sendWppBtn.addEventListener('click', openWppModal);
    closeWppModalBtn.addEventListener('click', () => wppModal.classList.add('hidden'));
    wppModal.addEventListener('click', (e) => { 
        if (e.target.id === 'wppModal') wppModal.classList.add('hidden'); 
    });
    wppContactListContainer.addEventListener('click', handleWppContactClick);

    // Listeners do Modal de Gerenciamento de Contatos (Abre/Fecha)
    openContactsModalBtn.addEventListener('click', () => contactsModal.classList.remove('hidden'));
    closeContactsModalBtn.addEventListener('click', () => contactsModal.classList.add('hidden'));
    contactsModal.addEventListener('click', (e) => { 
        if (e.target.id === 'contactsModal') contactsModal.classList.add('hidden'); 
    });

    // Listeners do Gerenciador de Contatos (no dbModal)
    addContactBtn.addEventListener('click', addContact);
    exportContactsCsvBtn.addEventListener('click', exportContactsCsv);

    contactsListContainer.addEventListener('click', (e) => {
        const deleteButton = e.target.closest('.delete-contact-btn');
        if (deleteButton) {
            const id = parseInt(deleteButton.dataset.id, 10);
            deleteContact(id);
        }
    });

    loadContactsCsvBtn.addEventListener('click', () => {
        const file = contactsCsvFileInput.files[0];
        if (!file) {
            showToast('Selecione um arquivo CSV de contatos.', 'error');
            return;
        }
        // Reusa a função loadCsvToDB
        loadCsvToDB(file, 'contacts', contactsDbStatus, contactsParser);
        // Recarrega a lista após a importação
        setTimeout(renderContactsList, 1000); 
    });
    
    // Inicialização
    /**
     * @functionality 500
     * @category 5xx: Utilitários e Validações
     * @name Inicialização de Data Atual no Campo de Análise
     * @description Define valor default como data de hoje em formato YYYY-MM-DD.
     */
    const today = new Date().toISOString().split('T')[0];
    analysisDateInput.value = today;
    populateDocNames(); 
    initDb();
    renderFooter();
    setupAdminModeToggle();
    updateAdminControlsState(); // Define o estado inicial dos controles de admin


});



