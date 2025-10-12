document.addEventListener('DOMContentLoaded', function () {
    // --- INFORMAÇÕES DA APLICAÇÃO ---
    const APP_AUTHOR = "Kevin Fróes";
    const APP_NAME = "Gerador de Mensagens";
    const APP_VERSION = "2.5.3"; // Versão incrementada para refletir a correção
    const APP_VERSION_DATE = "12/10/2025";

    // --- VARIÁVEIS DE ESTADO ---
    let db;
    let encryptionKey = null;
    let titleClickCount = 0;

    // --- ELEMENTOS DO DOM ---
    const dbName = "CafDatabase";
    const dbVersion = 4;
    const dbStatus = document.getElementById('db-status');
    const familyDbStatus = document.getElementById('family-db-status');
    const cnpjInputForDb = document.getElementById('cnpj');
    const companyNameInputForDb = document.getElementById('companyName');
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

    // --- FUNÇÕES GERAIS E DE UTILIDADE ---

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
    
    function renderFooter() {
        const footer = document.getElementById('appVersionInfo');
        if (footer) footer.textContent = `${APP_AUTHOR} - ${APP_NAME} Versão ${APP_VERSION} de ${APP_VERSION_DATE}`;
    }

    // --- LÓGICA DE CRIPTOGRAFIA ---

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
        
        // CORREÇÃO: Processa o array em blocos para evitar o erro de call stack
        let binaryString = '';
        const CHUNK_SIZE = 8192;
        for (let i = 0; i < finalData.length; i += CHUNK_SIZE) {
            const chunk = finalData.subarray(i, i + CHUNK_SIZE);
            binaryString += String.fromCharCode.apply(null, chunk);
        }
        return btoa(binaryString);
    }

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

            initializeAppLogic();

        } catch (e) {
            showToast('Erro ao processar a senha.', 'error');
        }
    }
    
    function handleLogout() {
        localStorage.removeItem('encryptionKey');
        sessionStorage.removeItem('encryptionKey');
        location.reload();
    }
    
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

    async function calculateHash(text) {
        const encoder = new TextEncoder();
        const data = encoder.encode(text);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        return hashHex;
    }

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
    
    function updateExportModalState() {
        const isAdmin = sessionStorage.getItem('adminModeUnlocked') === 'true';
        const exportCompanies = document.getElementById('exportCompanies');
        const exportFamilies = document.getElementById('exportFamilies');
        const exportHistory = document.getElementById('exportHistory');

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
        
        if (isAdmin) {
            exportCompanies.checked = true;
            exportFamilies.checked = true;
            exportHistory.checked = false;
        } else {
            exportCompanies.checked = false;
            exportFamilies.checked = false;
            exportHistory.checked = true;
        }
    }

    function setupAdminModeToggle() {
        appTitle.addEventListener('click', () => {
            titleClickCount++;
            if (titleClickCount >= 7) {
                sessionStorage.setItem('adminModeUnlocked', 'true');
                showToast('Modo Admin Ativado!', 'success');
                updateExportModalState();
                titleClickCount = 0;
            }
            setTimeout(() => { titleClickCount = 0; }, 2000);
        });
    }

    // --- INICIALIZAÇÃO E LÓGICA DO BANCO DE DADOS ---
    
    async function initializeAppLogic() {
        await checkForUpdates();
        checkDbStatus('companies', dbStatus, 'registros');
        checkDbStatus('families', familyDbStatus, 'famílias');
    }

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
        };

        request.onsuccess = async function(event) {
            db = event.target.result;

            encryptionKey = await getStoredKey();

            if (encryptionKey) {
                logoutBtn.classList.remove('hidden');
                initializeAppLogic();
            } else {
                try {
                    const response = await fetch('backup.json');
                    if (response.ok) {
                        passwordPromptMessage.textContent = "Uma base de dados central foi encontrada. Por favor, insira a senha mestra para acessá-la.";
                        passwordModal.classList.remove('hidden');
                    } else {
                        console.log("Nenhum backup central encontrado. Iniciando em modo de bootstrapping.");
                        initializeAppLogic();
                    }
                } catch (error) {
                    console.log("Não foi possível acessar o backup central. Iniciando em modo offline/bootstrapping.");
                    initializeAppLogic();
                }
            }
        };

        request.onerror = function(event) {
            showToast('Erro crítico ao acessar o banco de dados local.', 'error');
        };
    }

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
            if (options.includeHistory) storesToExport.push('history');
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
            
            if (options.includeHistory) {
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
    
    function saveMessageToHistory(messageData) {
        if (!db) return;
        const transaction = db.transaction(['history'], 'readwrite');
        const store = transaction.objectStore('history');
        store.put(messageData);
    }

    async function renderHistory() {
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

        if (allRecords.length === 0) {
            container.innerHTML = '<p class="text-gray-500 text-center">Nenhum histórico encontrado.</p>';
            return;
        }

        container.innerHTML = '';
        allRecords.reverse().forEach(item => {
            const date = new Date(item.timestamp);
            const formattedDate = date.toLocaleString('pt-BR');
            const element = document.createElement('div');
            element.className = 'border rounded-lg bg-white shadow-sm overflow-hidden';
            element.innerHTML = `
                <div class="p-3 flex justify-between items-center bg-gray-50 border-b">
                    <div class="flex-grow">
                        <p class="font-bold text-blue-700">${item.companyName}</p>
                        <p class="text-sm text-gray-600">${item.cnpj}</p>
                        <p class="text-xs text-gray-400 mt-1">Gerado em: ${formattedDate}</p>
                    </div>
                    <div class="flex items-center space-x-2 ml-2">
                        <button data-id="${item.id}" class="delete-history-btn text-red-500 hover:text-red-700 font-bold p-1 text-lg leading-none">&times;</button>
                        <button data-message="${encodeURIComponent(item.message)}" class="copy-history-btn bg-gray-200 text-gray-700 font-semibold py-1 px-3 rounded-lg hover:bg-gray-300 transition text-xs">Copiar</button>
                        <button class="expand-history-btn text-blue-600 font-semibold text-xs py-1 px-3">Expandir</button>
                    </div>
                </div>
                <div class="history-message-content">
                    <pre class="p-4 text-xs text-gray-800 whitespace-pre-wrap font-sans">${item.message}</pre>
                </div>
            `;
            container.appendChild(element);
        });
    }

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

    // --- LÓGICA PRINCIPAL DA APLICAÇÃO ---

    const companyParser = (line) => {
        const parts = line.split(';;');
        if (parts.length >= 2) {
            const cnpj = parts[0].trim().replace(/\D/g, '');
            const razaoSocial = parts[1]?.trim();
            if (cnpj && razaoSocial) return { cnpj, razaoSocial };
        }
        return null;
    }

    const familyParser = (line) => {
        const parts = line.split(';;');
        if (parts.length >= 3) {
            const id = parts[0]?.trim();
            const description = parts[2]?.trim();
            if(id && description) return { id, description };
        }
        return null;
    }

    function searchCnpj(doc) {
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
                cnpjStatusSpan.textContent = 'Encontrado';
                cnpjStatusSpan.className = 'text-green-600';
            } else {
                companyNameInputForDb.value = '';
                cnpjStatusSpan.textContent = 'Não encontrado';
                cnpjStatusSpan.className = 'text-red-600';
            }
        };
         request.onerror = function(event) {
             cnpjStatusSpan.textContent = 'Erro';
             cnpjStatusSpan.className = 'text-red-600';
         }
    }
    
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

    function resetFormFields() {
        document.getElementById('statusDeferida').checked = true;
        registrationTypeInput.value = 'CRC';
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

    const formatDate = (dateString) => {
        if (!dateString) return '';
        const [year, month, day] = dateString.split('-');
        return `${day}/${month}/${year}`;
    };
    
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
                    <p class="font-bold text-blue-700">${doc.category}</p>
                    <p class="text-gray-800">${docDisplayName}</p>
                    <p class="text-gray-500 italic">Motivo: ${doc.reason}</p>
                </div>
                <button data-index="${index}" class="remove-doc-btn text-red-500 hover:text-red-700 font-bold p-1">&times;</button>
            `;
            rejectedDocsListContainer.appendChild(docElement);
        });
    };
    
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
    openDbModalBtn.addEventListener('click', () => dbModal.classList.remove('hidden'));
    closeDbModalBtn.addEventListener('click', () => dbModal.classList.add('hidden'));
    dbModal.addEventListener('click', (e) => { if (e.target.id === 'dbModal') dbModal.classList.add('hidden'); });
    
    openHistoryModalBtn.addEventListener('click', () => {
        historyModal.classList.remove('hidden');
        renderHistory();
    });
    closeHistoryModalBtn.addEventListener('click', () => historyModal.classList.add('hidden'));
    historyModal.addEventListener('click', (e) => { if (e.target.id === 'historyModal') historyModal.classList.add('hidden'); });

    document.getElementById('exportDbBtn').addEventListener('click', () => {
        updateExportModalState();
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
            includeHistory: document.getElementById('exportHistory').checked
        };
        processExport(options);
        exportModal.classList.add('hidden');
    });

    // Banco de Dados e Histórico
    document.getElementById('loadCsvBtn').addEventListener('click', () => {
         const file = document.getElementById('csvFile').files[0];
         loadCsvToDB(file, 'companies', dbStatus, companyParser);
    });
    document.getElementById('loadFamilyCsvBtn').addEventListener('click', () => {
         const file = document.getElementById('familyCsvFile').files[0];
         loadCsvToDB(file, 'families', familyDbStatus, familyParser);
    });
    cnpjInputForDb.addEventListener('input', (e) => {
        let v = e.target.value.replace(/\D/g, '');
        if (v.length <= 11) {
            v = v.replace(/(\d{3})(\d)/, '$1.$2');
            v = v.replace(/(\d{3})(\d)/, '$1.$2');
            v = v.replace(/(\d{3})(\d{1,2})$/, '$1-$2');
        } else {
            v = v.replace(/^(\d{2})(\d)/, '$1.$2');
            v = v.replace(/^(\d{2})\.(\d{3})(\d)/, '$1.$2.$3');
            v = v.replace(/\.(\d{3})(\d)/, '.$1/$2');
            v = v.replace(/(\d{4})(\d)/, '$1-$2');
        }
        e.target.value = v;
        resetFormFields(); 
        searchCnpj(e.target.value);
    });

    document.getElementById('importDbFile').addEventListener('change', importDatabase);
    document.getElementById('clearHistoryBtn').addEventListener('click', clearHistory);

    // Formulário principal
    statusRadios.forEach(radio => radio.addEventListener('change', toggleRejectedDocsSection));
    addDocBtn.addEventListener('click', addRejectedDoc);
    generateBtn.addEventListener('click', generateMessage);
    copyBtn.addEventListener('click', () => copyToClipboard(resultText.value));
    docCategoryInput.addEventListener('change', populateDocNames);
    docNameSelect.addEventListener('change', handleDocNameChange);
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
            if (content.style.maxHeight) {
                content.style.maxHeight = null;
                target.textContent = 'Expandir';
            } else {
                content.style.maxHeight = content.scrollHeight + "px";
                target.textContent = 'Recolher';
            }
        }
    });

    contactMadeCheckbox.addEventListener('change', () => {
        contactDetailsWrapper.classList.toggle('hidden', !contactMadeCheckbox.checked);
    });

    // Event Listeners de Autenticação
    passwordForm.addEventListener('submit', handlePasswordSubmit);
    logoutBtn.addEventListener('click', handleLogout);
    
    // Inicialização
    const today = new Date().toISOString().split('T')[0];
    analysisDateInput.value = today;
    populateDocNames(); 
    initDb();
    renderFooter();
    setupAdminModeToggle();

});