document.addEventListener('DOMContentLoaded', function() {
    const analysisCache = new Map();

    function getCookie(name) {
        let cookieValue = null;
        if (document.cookie && document.cookie !== '') {
            const cookies = document.cookie.split(';');
            for (let i = 0; i < cookies.length; i++) {
                const cookie = cookies[i].trim();
                if (cookie.substring(0, name.length + 1) === (name + '=')) {
                    cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                    break;
                }
            }
        }
        return cookieValue;
    }

    const phishingDetector = {
        phishingKeywords: [
            'заблокирован', 'срочно', 'verify', 'account', 'password',
            'карта', 'click here', 'требует', 'подтвердите', 'urgent',
            'invoice', 'payment', 'требуется', 'обновить', 'security'
        ],
        safeKeywords: [
            'добрый день', 'прикрепляю', 'документ', 'отчет',
            'коллега', 'проект', 'уведомление', 'встреча',
            'совещание', 'документ', 'проверьте', 'отчет'
        ],

        preprocessText(text) {
            text = text.toLowerCase().trim();
            text = text.replace(/[^\w\s@./-]/g, '');
            return text;
        },

        async analyzeText(text) {
            const cacheKey = text.slice(0, 100);
            if (analysisCache.has(cacheKey)) {
                return analysisCache.get(cacheKey);
            }

            try {
                const cleanText = this.preprocessText(text);
                const originalText = text.toLowerCase();
                const hasUrl = /(https?:\/\/\S+|www\.\S+)/i.test(originalText);
                const hasPhishingKw = this.phishingKeywords.some(kw => cleanText.includes(kw));
                const hasSafeKw = this.safeKeywords.some(kw => cleanText.includes(kw));
                const isShortText = cleanText.length < 10; // Проверка на короткий текст

                console.log('Analyzing text:', {
                    cleanText: cleanText.slice(0, 50),
                    hasUrl,
                    hasPhishingKw,
                    hasSafeKw,
                    isShortText
                });

                // Серверный инференс
                console.log('Sending text to server for analysis:', cleanText.slice(0, 50));
                const response = await fetch('https://mymessenger.local:8443/chat/tokenize/', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'X-CSRFToken': getCookie('csrftoken')
                    },
                    body: new URLSearchParams({ 'text': cleanText })
                });
                const result = await response.json();
                if (result.error) throw new Error(result.error);

                console.log('Server analysis result:', result);

                // Обработка результата
                const classMapping = {
                    0: 'phishing',
                    1: 'phishing_url',
                    2: 'legitimate',
                    3: 'legitimate_url'
                };
                const label = classMapping[result.predClass];
                let isPhishing = label.includes('phishing');
                let confidence = result.maxProb;
                let reason = label;

                // Корректировка для коротких текстов
                if (isShortText) {
                    if (!hasPhishingKw && !hasUrl) {
                        isPhishing = false;
                        confidence = Math.max(0.1, confidence - 0.5);
                        reason = 'short_text_no_phishing_indicators';
                        console.log('Short text override:', { isPhishing, confidence, reason });
                    }
                } else {
                    // Стандартная логика ключевых слов
                    if (isPhishing) {
                        if (hasSafeKw && !hasUrl) {
                            isPhishing = false;
                            confidence = Math.max(0.1, confidence - 0.3);
                            reason = 'safe_keyword_override';
                        } else if (hasUrl && hasPhishingKw) {
                            confidence = Math.min(1.0, confidence + 0.15);
                        }
                    } else {
                        if (hasUrl && hasPhishingKw) {
                            isPhishing = true;
                            confidence = Math.max(confidence, 0.85);
                            reason = 'url_with_phishing_keywords';
                        }
                    }
                }

                console.log('Final analysis:', { isPhishing, confidence, reason });

                const analysisResult = {
                    is_phishing: isPhishing,
                    reason,
                    confidence: Number(confidence.toFixed(4)),
                    details: {
                        text_sample: cleanText.slice(0, 100) + (cleanText.length > 100 ? '...' : ''),
                        has_url: hasUrl,
                        has_phishing_keywords: hasPhishingKw,
                        has_safe_keywords: hasSafeKw,
                        model_label: label,
                        model_confidence: result.maxProb
                    }
                };

                analysisCache.set(cacheKey, analysisResult);
                if (analysisCache.size > 1000) {
                    analysisCache.delete(analysisCache.keys().next().value);
                }

                return analysisResult;
            } catch (e) {
                console.error('Phishing analysis error:', e);
                return {
                    is_phishing: false,
                    reason: 'error',
                    confidence: 0.0,
                    details: { error: true, message: 'Ошибка при анализе текста' }
                };
            }
        },

        resolveResult(predClass, maxProb) {
            console.log('Resolved:', { predClass, maxProb });
        }
    };

    async function initPhishingDetector() {
        //console.log('Initializing phishing detector');
        const modelLoading = document.getElementById('modelLoading');
        if (modelLoading) modelLoading.style.display = 'block';

        try {
            //console.log('Phishing detector setup completed');
            if (modelLoading) modelLoading.style.display = 'none';
            return true;
        } catch (e) {
            console.error('Failed to initialize phishing detector:', e);
            if (modelLoading) modelLoading.style.display = 'none';
            return false;
        }
    }

    // --- Проверка и расшифровка приватного ключа ---
    async function checkPrivateKey() {
        const sessionPrivateKey = sessionStorage.getItem('sessionPrivateKey');

        if (sessionPrivateKey) {
            window.sessionPrivateKey = sessionPrivateKey;
            return true;
        }

        try {
            const response = await fetch('/accounts/get-private-key/', {
                method: 'GET',
                headers: {
                    'Accept': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                credentials: 'include'
            });
            const data = await response.json();

            if (data.status === 'success' && data.private_key && data.key_salt) {
                console.log('Received private_key and key_salt from server');
                sessionStorage.setItem('encryptedPrivateKey', data.private_key);
                sessionStorage.setItem('keySalt', data.key_salt);
                const decryptModal = document.querySelector('#decryptModal');
                if (decryptModal) {
                    console.log('Showing decrypt modal');
                    const bootstrapModal = new bootstrap.Modal(decryptModal);
                    bootstrapModal.show();
                    return false;
                } else {
                    console.error('Decrypt modal not found');
                    alert('Ошибка: Модальное окно для расшифровки недоступно. Перелогинитесь.');
                    window.location.href = '/accounts/login/';
                    return false;
                }
            } else {
                throw new Error(data.message || 'Failed to fetch private key');
            }
        } catch (e) {
            console.error('Error fetching private key:', e);
            alert('Ошибка: Не удалось получить ключ. Перелогинитесь.');
            window.location.href = '/accounts/login/';
            return false;
        }
    }

    // Обработчик формы расшифровки
    const decryptForm = document.querySelector('#decryptForm');
    if (decryptForm) {
        decryptForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            const decryptPassword = document.querySelector('#decryptPassword');
            const password = decryptPassword.value;
            const encryptedPrivateKey = sessionStorage.getItem('encryptedPrivateKey');
            const keySalt = sessionStorage.getItem('keySalt');

            if (!encryptedPrivateKey || !keySalt) {
                console.error('Missing encryptedPrivateKey or keySalt');
                alert('Ошибка: Данные для расшифровки недоступны. Перелогинитесь.');
                window.location.href = '/accounts/login/';
                return;
            }

            try {
                console.log('Attempting to decrypt private key in chat');
                const salt = new Uint8Array(keySalt.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
                const enc = new TextEncoder();
                const keyMaterial = await crypto.subtle.importKey(
                    'raw',
                    enc.encode(password),
                    'PBKDF2',
                    false,
                    ['deriveBits']
                );
                const derivedBits = await crypto.subtle.deriveBits(
                    {
                        name: 'PBKDF2',
                        salt: salt,
                        iterations: 100000,
                        hash: 'SHA-256'
                    },
                    keyMaterial,
                    256
                );
                const derivedKey = await crypto.subtle.importKey(
                    'raw',
                    derivedBits,
                    'AES-GCM',
                    false,
                    ['decrypt']
                );
                const encryptedKey = new Uint8Array(atob(encryptedPrivateKey).split('').map(c => c.charCodeAt(0)));
                const iv = encryptedKey.slice(0, 12);
                const data = encryptedKey.slice(12);
                const decrypted = await crypto.subtle.decrypt(
                    {
                        name: 'AES-GCM',
                        iv: iv,
                        tagLength: 128
                    },
                    derivedKey,
                    data
                );
                window.sessionPrivateKey = new TextDecoder().decode(decrypted);
                sessionStorage.setItem('sessionPrivateKey', window.sessionPrivateKey);
                console.log('Private key decrypted in chat:', window.sessionPrivateKey ? 'Success' : 'Failed');
                const bootstrapModal = bootstrap.Modal.getInstance(document.querySelector('#decryptModal'));
                bootstrapModal.hide();
                decryptPassword.value = '';
                sessionStorage.removeItem('encryptedPrivateKey');
                sessionStorage.removeItem('keySalt');
                chatApp.init();
                initWebSocket();
                initUI();
            } catch (e) {
                console.error('Decryption error:', e);
                alert('Ошибка расшифровки. Проверьте пароль.');
            }
        });
    }

    async function encryptSessionKey(sessionKey, publicKeyPem) {
        try {
            const pemContents = publicKeyPem
                .replace(/-----(BEGIN|END) PUBLIC KEY-----|\n/g, '')
                .trim();
            const binaryDer = new Uint8Array(atob(pemContents).split('').map(c => c.charCodeAt(0)));
            const publicKey = await crypto.subtle.importKey(
                'spki',
                binaryDer,
                { name: 'RSA-OAEP', hash: 'SHA-256' },
                false,
                ['encrypt']
            );
            const exportedKey = await crypto.subtle.exportKey('raw', sessionKey);
            const encryptedKey = await crypto.subtle.encrypt(
                { name: 'RSA-OAEP' },
                publicKey,
                exportedKey
            );
            return btoa(String.fromCharCode(...new Uint8Array(encryptedKey)));
        } catch (e) {
            console.error('Session key encryption error:', e);
            throw e;
        }
    }

    async function decryptSessionKey(encryptedKey, privateKeyPem) {
        try {
            const pemContents = privateKeyPem
                .replace(/-----(BEGIN|END) PRIVATE KEY-----|\n/g, '')
                .trim();
            const binaryDer = new Uint8Array(atob(pemContents).split('').map(c => c.charCodeAt(0)));
            const privateKey = await crypto.subtle.importKey(
                'pkcs8',
                binaryDer,
                { name: 'RSA-OAEP', hash: 'SHA-256' },
                false,
                ['decrypt']
            );
            const encryptedKeyBytes = new Uint8Array(atob(encryptedKey).split('').map(c => c.charCodeAt(0)));
            const decryptedKey = await crypto.subtle.decrypt(
                { name: 'RSA-OAEP' },
                privateKey,
                encryptedKeyBytes
            );
            return crypto.subtle.importKey(
                'raw',
                decryptedKey,
                'AES-GCM',
                true,
                ['encrypt', 'decrypt']
            );
        } catch (e) {
            console.error('Session key decryption error:', e);
            throw e;
        }
    }

    async function encryptMessage(message, sessionKey) {
        try {
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const enc = new TextEncoder();
            const encrypted = await crypto.subtle.encrypt(
                {
                    name: 'AES-GCM',
                    iv: iv,
                    tagLength: 128
                },
                sessionKey,
                enc.encode(message)
            );
            const ciphertext = encrypted.slice(0, -16);
            const tag = encrypted.slice(-16);
            return {
                content: btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
                iv: btoa(String.fromCharCode(...iv)),
                tag: btoa(String.fromCharCode(...new Uint8Array(tag)))
            };
        } catch (e) {
            console.error('Message encryption error:', e);
            throw e;
        }
    }

    async function decryptMessage(encryptedData, sessionKey) {
        try {
            // Декодируем base64 в Uint8Array
            const decodeBase64 = (str) => {
                const binaryString = atob(str);
                const len = binaryString.length;
                const bytes = new Uint8Array(len);
                for (let i = 0; i < len; i++) {
                    bytes[i] = binaryString.charCodeAt(i);
                }
                return bytes;
            };

            const iv = decodeBase64(encryptedData.iv);
            const tag = decodeBase64(encryptedData.tag);
            const ciphertext = decodeBase64(encryptedData.content);

            // Собираем зашифрованные данные с тегом
            const encryptedWithTag = new Uint8Array(ciphertext.length + tag.length);
            encryptedWithTag.set(ciphertext);
            encryptedWithTag.set(tag, ciphertext.length);

            // Расшифровка
            const decrypted = await crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: iv,
                    tagLength: 128
                },
                sessionKey,
                encryptedWithTag
            );

            // Преобразуем в строку (для текстовых сообщений)
            return new TextDecoder().decode(decrypted);
        } catch (error) {
            console.error('Message decryption error:', error);
            throw error;
        }
    }

    async function getPublicKey(userId) {
        try {
            console.log('Fetching public key for user:', userId);
            const response = await fetch(`/chat/get-public-key/${userId}/`, {
                headers: {
                    'Accept': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                }
            });
            const data = await response.json();
            if (data.status === 'success') {
                console.log('Public key:', data.public_key);
                return data.public_key;
            } else {
                throw new Error(data.message || 'Failed to fetch public key');
            }
        } catch (e) {
            console.error('Error fetching public key:', e);
            throw e;
        }
    }

    async function getSessionKey(chatId) {
        try {
            const cachedKey = sessionStorage.getItem(`chat_${chatId}_sessionKey`);
            if (cachedKey) {
                const keyBytes = new Uint8Array(atob(cachedKey).split('').map(c => c.charCodeAt(0)));
                return crypto.subtle.importKey(
                    'raw',
                    keyBytes,
                    'AES-GCM',
                    true,
                    ['encrypt', 'decrypt']
                );
            }

            const response = await fetch(`/chat/get-session-key/${chatId}/`, {
                headers: {
                    'Accept': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                }
            });
            const data = await response.json();
            if (data.status === 'success') {
                const sessionKey = await decryptSessionKey(data.encrypted_key, window.sessionPrivateKey);
                const exportedKey = await crypto.subtle.exportKey('raw', sessionKey);
                sessionStorage.setItem(`chat_${chatId}_sessionKey`, btoa(String.fromCharCode(...new Uint8Array(exportedKey))));
                return sessionKey;
            } else {
                throw new Error(data.message || 'Failed to fetch session key');
            }
        } catch (e) {
            console.error('Error fetching session key:', e);
            throw e;
        }
    }

    function extractUrls(text) {
        const urlRegex = /(?:https?:\/\/|www\.)(?:[^\s<>"]+\.)+[^\s<>"/]+(?:\/[^\s<>"]*)?/g;
        const urls = text.match(urlRegex) || [];
        console.log('Extracted URLs from text:', { text, urls });
        return urls.filter(url => {
            try {
                new URL(url.startsWith('www.') ? 'http://' + url : url);
                return true;
            } catch {
                return false;
            }
        });
    }

    const chatHeader = document.querySelector('.chat-header');
    const chatType = chatHeader ? chatHeader.dataset.chatType : null;
    const recipientIdScript = document.getElementById('recipientId');
    const recipientId = recipientIdScript ? JSON.parse(recipientIdScript.textContent) : null;

    if (chatType === 'DM' && recipientId) {
        chatHeader.dataset.recipientId = recipientId;
    }

    const chatApp = {
        init() {
            this.cacheElements();
            this.bindEvents();
        },

        cacheElements() {
            this.modal = document.getElementById('createChatModal');
            this.userSearch = document.getElementById('userSearch');
            this.userList = document.getElementById('userList');
            this.createBtn = document.getElementById('confirmCreate');
            this.csrfToken = document.querySelector('input[name="csrfmiddlewaretoken"]')?.value ||
                            document.cookie.match(/csrftoken=([^;]+)/)?.[1];
            this.baseUrl = document.body.dataset.baseUrl || '';
            this.createChatUrl = document.body.dataset.createChatUrl || '/chat/create-chat/';
            this.getUsersUrl = document.body.dataset.getUsersUrl || '/chat/get-users/';
        },

        bindEvents() {
            if (this.modal) {
                this.modal.addEventListener('show.bs.modal', () => this.loadUsers());
            }

            if (this.userSearch) {
                this.userSearch.addEventListener('input', (e) => this.filterUsers(e.target.value));
            }

            if (this.createBtn) {
                this.createBtn.addEventListener('click', () => this.handleCreateChat());
            }
        },

        async loadUsers() {
            try {
                console.log('Fetching users from:', `${this.baseUrl}${this.getUsersUrl}`);
                const response = await fetch(`${this.baseUrl}${this.getUsersUrl}`, {
                    method: 'GET',
                    headers: {
                        'Accept': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest'
                    },
                    credentials: 'include'
                });

                if (response.status === 401 || response.status === 403) {
                    console.error('User not authenticated');
                    alert('Пожалуйста, войдите в систему');
                    window.location.href = '/accounts/login/';
                    return;
                }

                if (!response.ok) {
                    const text = await response.text();
                    console.error('Server response:', text);
                    throw new Error(`HTTP error: ${response.status} - ${text.slice(0, 100)}`);
                }

                const data = await response.json();
                if (data.status !== 'success') {
                    throw new Error(data.message || 'Ошибка сервера');
                }

                this.renderUsers(data.users);
            } catch (error) {
                console.error('Ошибка загрузки пользователей:', error);
                this.showError(error.message || 'Не удалось загрузить пользователей');
            }
        },

        renderUsers(users) {
            if (!this.userList) return;
            this.userList.innerHTML = users.map(user => `
                <label class="list-group-item d-flex gap-2">
                    <input class="form-check-input flex-shrink-0" type="checkbox" value="${user.id}">
                    <span>${user.username}</span>
                </label>
            `).join('');
        },

        filterUsers(searchTerm) {
            if (!this.userList) return;
            const term = searchTerm.toLowerCase();
            this.userList.querySelectorAll('label').forEach(item => {
                const name = item.textContent.toLowerCase();
                item.style.display = name.includes(term) ? 'flex' : 'none';
            });
        },

        async handleCreateChat() {
            const selectedUsers = this.getSelectedUsers();

            if (selectedUsers.length < 1) {
                this.showError('Выберите хотя бы одного другого участника');
                return;
            }
            console.log('Selected users:', selectedUsers);

            // Очистка предыдущей ошибки
            const errorElement = document.getElementById('createChatError');
            if (errorElement) {
                errorElement.textContent = '';
                errorElement.style.display = 'none';
            }

            try {
                const sessionKey = await crypto.subtle.generateKey(
                    { name: 'AES-GCM', length: 256 },
                    true,
                    ['encrypt', 'decrypt']
                );

                const currentUserId = document.body.dataset.currentUserId;
                console.log('Current user:', currentUserId);
                if (!currentUserId) {
                    throw new Error('Current user ID is missing in chat header');
                }
                const userIds = selectedUsers.concat([currentUserId]);

                const encryptedSessionKeys = {};
                for (const userId of userIds) {
                    const publicKey = await getPublicKey(userId);
                    encryptedSessionKeys[userId] = await encryptSessionKey(sessionKey, publicKey);
                }

                const response = await fetch(`${this.baseUrl}${this.createChatUrl}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': this.csrfToken,
                        'X-Requested-With': 'XMLHttpRequest'
                    },
                    credentials: 'include',
                    body: JSON.stringify({
                        users: selectedUsers,
                        encrypted_session_keys: encryptedSessionKeys
                    })
                });

                const data = await response.json();

                if (data.status === 'success' || data.status === 'exists') {
                    const exportedKey = await crypto.subtle.exportKey('raw', sessionKey);
                    sessionStorage.setItem(`chat_${data.chat_id}_sessionKey`, btoa(String.fromCharCode(...new Uint8Array(exportedKey))));
                    window.location.href = `${this.baseUrl}/chat/?chat_id=${data.chat_id}`;
                } else {
                    console.error('Error creating chat:', data.message);
                    this.showError(data.message || 'Неизвестная ошибка');
                }
            } catch (error) {
                console.error('Create chat error:', error);
                this.showError(error.message || 'Ошибка соединения');
            }
        },

        getSelectedUsers() {
            if (!this.userList) return [];
            return Array.from(
                this.userList.querySelectorAll('input:checked')
            ).map(el => el.value);
        },

        showError(message) {
            alert(message);
        }
    };

    async function decryptLastMessages() {
        const chatItems = document.querySelectorAll('.chat-list .chat-item');
        for (const chatItem of chatItems) {
            const chatId = new URL(chatItem.href).searchParams.get('chat_id');
            const encryptedContent = chatItem.dataset.encryptedContent;
            const fileData = chatItem.dataset.fileData;
            const iv = chatItem.dataset.iv;
            const tag = chatItem.dataset.tag;
            const lastMessageElement = chatItem.querySelector('.last-message');
            const chatType = chatItem.dataset.chatType || 'DM';

//            console.log("chatId:", chatId);
//            console.log("iv:", iv);
//            console.log("tag:", tag);
//            console.log("encryptedContent:", encryptedContent);
//            console.log("fileData:", fileData);
//            console.log("lastMessageElement:", lastMessageElement);
//            console.log("textContent:", lastMessageElement.textContent);

            if (iv && tag && lastMessageElement && lastMessageElement.textContent !== 'Нет сообщений') {
                try {
                    const sessionKey = await getSessionKey(chatId);

                    if (fileData) {
                        lastMessageElement.textContent = encryptedContent || '[Файл]';
                    } else if (encryptedContent) {
                        const messageText = await decryptMessage(
                            { content: encryptedContent, iv: iv, tag: tag },
                            sessionKey
                        );
                        lastMessageElement.textContent = messageText.length > 25 ? messageText.substring(0, 22) + '...' : messageText;
                    } else {
                        lastMessageElement.textContent = '[Пустое сообщение]';
                    }
                } catch (e) {
                    console.error('Failed to decrypt last message for chat', chatId, ':', e);
                    lastMessageElement.textContent = '[Ошибка расшифровки]';
                }
            }
        }
    }

    const sidebarToggle = document.getElementById('sidebarToggle');
    const sidebarMenu = document.getElementById('sidebarMenu');

    if (sidebarToggle && sidebarMenu) {
        // Показываем/скрываем меню по клику на гамбургер
        sidebarToggle.addEventListener('click', function(e) {
            e.stopPropagation();
            sidebarMenu.style.display = sidebarMenu.style.display === 'block' ? 'none' : 'block';
        });

        // Скрываем меню при клике вне его
        document.addEventListener('click', function() {
            sidebarMenu.style.display = 'none';
        });

        // Предотвращаем закрытие при клике внутри меню
        sidebarMenu.addEventListener('click', function(e) {
            e.stopPropagation();
        });
    } else {
        console.warn('Sidebar elements (#sidebarToggle or #sidebarMenu) not found');
    }

    // Логика поиска по чатам
    const searchInput = document.querySelector('.search-input');
    const chatItems = document.querySelectorAll('.chat-item');

    if (searchInput && chatItems.length > 0) {
        searchInput.addEventListener('input', function() {
            const searchTerm = this.value.toLowerCase();

            chatItems.forEach(item => {
                const chatName = item.querySelector('.chat-info h4')?.textContent.toLowerCase() || '';
                const lastMessage = item.querySelector('.last-message')?.textContent.toLowerCase() || '';

                if (chatName.includes(searchTerm) || lastMessage.includes(searchTerm)) {
                    item.style.display = 'flex';
                } else {
                    item.style.display = 'none';
                }
            });
        });
    } else {
        console.warn('Search input (.search-input) or chat items (.chat-item) not found');
    }

    async function initWebSocket() {
        const chatHeader = document.querySelector('.chat-header');
        if (!chatHeader) return;

        const chatId = chatHeader.dataset.chatId;
        const chatType = chatHeader.dataset.chatType;
        const protocol = window.location.protocol === 'https:' ? 'wss://' : 'ws://';
        const wsUrl = `${protocol}mymessenger.local:8444/ws/chat/${chatId}/`;

        let sessionKey;
        try {
            sessionKey = await getSessionKey(chatId);
        } catch (e) {
            console.error('Failed to get session key:', e);
            alert('Ошибка: Не удалось получить сессионный ключ.');
            return;
        }

        await loadInitialMessages(chatId, sessionKey, chatType);
        await decryptLastMessages();

        window.chatSocket = new WebSocket(wsUrl);
        const messageForm = document.getElementById('message-form');
        const messageInput = document.getElementById('message-input');
        const fileInput = document.getElementById('file-input');

        if (!fileInput) {
            console.error('File input element not found');
            return;
        }

        window.chatSocket.onopen = function() {
            console.log('WebSocket connected');
        };

        let isUserRestricted = false;

        window.chatSocket.onmessage = async function(e) {
            try {
                const data = JSON.parse(e.data);
                console.log('Received message:', data);
                if (data.type === 'security_alert') {
                    if (data.alert_type === 'user_restricted') {
                        isUserRestricted = true;
                    }
                    showSecurityAlert(data.message, data.details, data.alert_type);
                }
                if (data.type === 'new_message') {
                    let messageText = data.message || '[Зашифрованное сообщение]';
                    let decryptedFileData = null;
                    const isCurrentUser = data.sender_id === parseInt(document.body.dataset.currentUserId);

                    // Расшифровываем текстовое сообщение
                    if ((chatType === 'DM' || chatType === 'GM') && data.message && data.iv && data.tag) {
                        try {
                            console.log('Attempting to decrypt message with:', {
                                content: data.message,
                                iv: data.iv,
                                tag: data.tag
                            });
                            messageText = await decryptMessage(
                                { content: data.message, iv: data.iv, tag: data.tag },
                                sessionKey
                            );
                        } catch (e) {
                            console.error('Failed to decrypt message:', e);
                            console.log('Decryption error stack:', e.stack);
                            messageText = '[Ошибка расшифровки]';
                        }
                    }

                    // Расшифровываем file_data, если оно есть
                    if (data.file_data && data.iv && data.tag) {
                        try {
                            console.log('Attempting to decrypt file_data with:', {
                                content: data.file_data,
                                iv: data.iv,
                                tag: data.tag
                            });
                            decryptedFileData = await decryptFileData(
                                { content: data.file_data, iv: data.iv, tag: data.tag },
                                sessionKey
                            );
                        } catch (e) {
                            console.error('Failed to decrypt file_data:', e);
                            console.log('Decryption error stack:', e.stack);
                            decryptedFileData = null;
                        }
                    }

                    console.log('Adding message to chat:', { ...data, message: messageText, decryptedFileData });
                    addMessageToChat(
                        { ...data, message: messageText, decryptedFileData },
                        isCurrentUser,
                        chatType
                    );
                } else if (data.type === 'history') {
                    const messagesContainer = document.querySelector('.messages-container');
                    messagesContainer.innerHTML = '';
                    for (const msg of data.messages) {
                        const isCurrentUser = msg.sender_id === parseInt(document.body.dataset.currentUserId);
                        let messageText = msg.content || '[Зашифрованное сообщение]';
                        let decryptedFileData = null;

                        if ((chatType === 'DM' || chatType === 'GM') && msg.content && msg.iv && msg.tag) {
                            try {
                                console.log('Attempting to decrypt history message with:', {
                                    content: msg.content,
                                    iv: msg.iv,
                                    tag: msg.tag
                                });
                                messageText = await decryptMessage(
                                    { content: msg.content, iv: msg.iv, tag: msg.tag },
                                    sessionKey
                                );
                            } catch (e) {
                                console.error('Failed to decrypt history message:', e);
                                console.log('Decryption error stack:', e.stack);
                                messageText = '[Ошибка расшифровки]';
                            }
                        }

                        if (msg.file_data && msg.iv && msg.tag) {
                            try {
                                console.log('Attempting to decrypt history file_data with:', {
                                    content: msg.file_data,
                                    iv: msg.iv,
                                    tag: msg.tag
                                });
                                decryptedFileData = await decryptFileData(
                                    { content: msg.file_data, iv: msg.iv, tag: msg.tag },
                                    sessionKey
                                );
                            } catch (e) {
                                console.error('Failed to decrypt history file_data:', e);
                                console.log('Decryption error stack:', e.stack);
                                decryptedFileData = null;
                            }
                        }

                        addMessageToChat(
                            {
                                message: messageText,
                                sender: msg.sender__username,
                                sender_id: msg.sender_id,
                                message_id: msg.id,
                                iv: msg.iv,
                                tag: msg.tag,
                                timestamp: msg.timestamp,
                                is_read: msg.is_read,
                                is_suspicious: msg.is_suspicious || false,
                                file_name: msg.file_name,
                                file_size: msg.file_size,
                                file_data: msg.file_data,
                                decryptedFileData
                            },
                            isCurrentUser,
                            chatType
                        );
                    }
                } else if (data.type === 'security_alert') {
                    console.log('Showing security alert:', data);
                    showSecurityAlert(data.message, data.details.reason || JSON.stringify(data.details), data.alert_type);
                } else if (data.type === 'error') {
                    console.error('Error received:', data);
                    showSecurityAlert(`Ошибка: ${data.error}`, JSON.stringify(data.details), 'error');
                }
            } catch (error) {
                console.error('Error parsing message:', error);
                showSecurityAlert('Ошибка обработки сообщения', error.message, 'error');
            }
        };

        window.chatSocket.onerror = function(error) {
            console.error('WebSocket Error:', error);
            showSecurityAlert('Ошибка WebSocket', 'Не удалось установить соединение.', 'error');
        };

        window.chatSocket.onclose = function() {
            console.log('WebSocket disconnected');
            showSecurityAlert('Соединение закрыто', 'WebSocket-соединение было разорвано.', 'error');
        };

        messageForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            const message = messageInput.value.trim();

            if (message && chatSocket.readyState === WebSocket.OPEN) {
                if (chatType === 'DM' || chatType === 'GM') {
                    try {
                        const result = await phishingDetector.analyzeText(message);
                        console.log('Phishing analysis result:', result);
                        if (result.is_phishing && result.confidence > 0.7) {
                            const details = `Причина: ${result.reason}, Уверенность: ${(result.confidence * 100).toFixed(1)}%` +
                                (result.details.has_url ? ', Обнаружен URL' : '') +
                                (result.details.has_phishing_keywords ? ', Ключевые слова фишинга' : '');
                            showSecurityAlert(
                                'Обнаружено потенциально опасное сообщение!',
                                details,
                                'phishing_detected'
                            );
                            const urls = extractUrls(message);
                            chatSocket.send(JSON.stringify({
                                type: 'phishing_alert',
                                message_id: crypto.randomUUID(),
                                confidence: result.confidence,
                                reason: result.reason,
                                has_url: result.details.has_url,
                                url: urls.length > 0 ? urls[0] : '',
                                details: {
                                    has_phishing_keywords: result.details.has_phishing_keywords,
                                    has_safe_keywords: result.details.has_safe_keywords
                                }
                            }));
                            return;
                        }

                        const urls = extractUrls(message);
                        console.log('Sending message with URLs:', { message, urls });
                        const encryptedData = await encryptMessage(message, sessionKey);
                        //console.log('Encrypted data:', encryptedData);
                        chatSocket.send(JSON.stringify({
                            type: 'message',
                            content: encryptedData.content,
                            iv: encryptedData.iv,
                            tag: encryptedData.tag,
                            urls: urls
                        }));
                    } catch (e) {
                        console.error('Encryption failed:', e);
                        showSecurityAlert('Ошибка шифрования', 'Не удалось зашифровать сообщение.', 'error');
                        return;
                    }
                } else {
                    const urls = extractUrls(message);
                    console.log('Sending message with URLs:', { message, urls });
                    chatSocket.send(JSON.stringify({
                        type: 'message',
                        content: message,
                        urls: urls
                    }));
                }
                messageInput.value = '';
            }
        });

        // Обработчик загрузки файла
        if (fileInput) {
            const handleFileChange = async (e) => {
                console.log('File input changed event:', e);
                console.log('Files:', e.target.files);
                const file = e.target.files[0];
                if (!file) {
                    console.warn('No file selected, ignoring change event');
                    return;
                }

                if (window.chatSocket.readyState === WebSocket.OPEN) {
                    try {
                        console.log('Processing file:', file.name);
                        const fileContent = await file.arrayBuffer();
                        console.log('File content length:', fileContent.byteLength);

                        // Вычисляем SHA256 хэш файла
                        const hashBuffer = await crypto.subtle.digest('SHA-256', fileContent);
                        const hashArray = Array.from(new Uint8Array(hashBuffer));
                        const fileHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
                        console.log('Calculated file hash:', fileHash);

                        // Проверяем хэш через VirusTotal
                        let response = await fetch('/chat/check-file-hash/', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                                'X-CSRFToken': getCookie('csrftoken'),
                            },
                            body: JSON.stringify({ hash: fileHash }),
                        });

                        let result = await response.json();
                        if (result.error) {
                            throw new Error(result.error);
                        }

                        if (result.is_malicious) {
                            alert('Файл помечен как вредоносный (VirusTotal). Загрузка отклонена.');
                            fileInput.value = '';
                            return;
                        }

                        // Если хэш не найден, загружаем файл для полной проверки (ClamAV + VirusTotal)
                        if (result.needs_upload) {
                            console.log('Hash not found, uploading file for scanning...');
                            const formData = new FormData();
                            formData.append('file', file);

                            response = await fetch('/chat/upload-and-check-file/', {
                                method: 'POST',
                                headers: {
                                    'X-CSRFToken': getCookie('csrftoken'),
                                },
                                body: formData,
                            });

                            result = await response.json();
                            if (result.error) {
                                throw new Error(result.error);
                            }

                            if (result.is_malicious) {
                                alert('Файл помечен как вредоносный (VirusTotal/ClamAV). Загрузка отклонена.');
                                fileInput.value = '';
                                return;
                            }
                        }

                        // Шифруем и отправляем файл
                        const iv = crypto.getRandomValues(new Uint8Array(12));
                        const encrypted = await crypto.subtle.encrypt(
                            { name: 'AES-GCM', iv: iv, tagLength: 128 },
                            sessionKey,
                            fileContent
                        );
                        console.log('Encryption completed, encrypted length:', encrypted.byteLength);
                        const ciphertext = encrypted.slice(0, -16);
                        const tag = encrypted.slice(-16);

                        const arrayToBase64 = (array) => {
                            const chunkSize = 8192;
                            const bytes = new Uint8Array(array);
                            let binary = '';
                            for (let i = 0; i < bytes.length; i += chunkSize) {
                                const chunk = bytes.subarray(i, i + chunkSize);
                                binary += String.fromCharCode.apply(null, chunk);
                            }
                            return btoa(binary);
                        };

                        const encryptedFileData = arrayToBase64(ciphertext);
                        const ivB64 = arrayToBase64(iv);
                        const tagB64 = arrayToBase64(tag);

                        window.chatSocket.send(JSON.stringify({
                            type: 'message',
                            content: `File: ${file.name}`,
                            iv: ivB64,
                            tag: tagB64,
                            file_name: file.name,
                            file_size: file.size,
                            file_data: encryptedFileData
                        }));
                        setTimeout(() => {
                            fileInput.value = '';
                            console.log('File input value reset');
                        }, 0);
                    } catch (error) {
                        console.error('File encryption or check error:', error);
                        alert('Ошибка обработки файла: ' + error.message);
                    }
                } else {
                    alert('Ошибка: WebSocket-соединение не активно.');
                }
            };

            fileInput.addEventListener('change', handleFileChange, { once: false });
        } else {
            console.error('No file input element found with id="file-input"');
        }

        function showSecurityAlert(message, details = {}, alertType = 'generic') {
            const modalEl = document.getElementById('securityAlertModal');
            const messageEl = document.getElementById('securityAlertMessage');
            const detailsEl = document.getElementById('securityAlertDetails');
            const reportBtn = document.getElementById('reportLinkButton');
            const phishingBlockMessage = document.getElementById('phishingBlockMessage');

            if (!modalEl || !messageEl || !detailsEl || !reportBtn || !phishingBlockMessage) {
                console.error('Security alert modal elements missing');
                return;
            }

            // Очистка предыдущего содержимого
            messageEl.textContent = message;
            detailsEl.textContent = typeof details === 'object' ? JSON.stringify(details, null, 2) : details;
            phishingBlockMessage.style.display = alertType === 'phishing_detected' ? 'block' : 'none';

            // Инициализация модального окна
            const modal = new bootstrap.Modal(modalEl, {
                backdrop: true,
                keyboard: true
            });

            // Удаление всех существующих backdrop перед открытием
            document.querySelectorAll('.modal-backdrop').forEach(backdrop => backdrop.remove());

            // Открытие модального окна
            modal.show();

            // Обработчик события закрытия модального окна
            modalEl.addEventListener('hidden.bs.modal', function handleModalHidden() {
                // Удаление backdrop
                document.querySelectorAll('.modal-backdrop').forEach(backdrop => backdrop.remove());
                // Очистка стилей у body
                document.body.classList.remove('modal-open');
                document.body.style.overflow = '';
                document.body.style.paddingRight = '';
                // Удаляем обработчик, чтобы избежать накопления
                modalEl.removeEventListener('hidden.bs.modal', handleModalHidden);
            }, { once: true });
        }

        async function decryptFileData({ content, iv, tag }, key) {
            try {
                console.log('Decrypting file data with key:', key);
                console.log('Input file data:', { content: content.slice(0, 50), iv, tag });

                // Эффективное декодирование Base64
                const base64ToArray = (str) => {
                    const binaryString = atob(str);
                    const bytes = new Uint8Array(binaryString.length);
                    for (let i = 0; i < binaryString.length; i++) {
                        bytes[i] = binaryString.charCodeAt(i);
                    }
                    return bytes;
                };

                const ivArray = base64ToArray(iv);
                const tagArray = base64ToArray(tag);
                const contentArray = base64ToArray(content);

                const encryptedWithTag = new Uint8Array(contentArray.length + tagArray.length);
                encryptedWithTag.set(contentArray);
                encryptedWithTag.set(tagArray, contentArray.length);

                const decrypted = await crypto.subtle.decrypt(
                    {
                        name: 'AES-GCM',
                        iv: ivArray,
                        tagLength: 128
                    },
                    key,
                    encryptedWithTag
                );

                return new Uint8Array(decrypted);
            } catch (error) {
                console.error('DecryptFileData error:', error);
                throw error;
            }
        }

        async function loadInitialMessages(chatId, sessionKey, chatType) {
            const messages = document.querySelectorAll('.message-row');
            for (const message of messages) {
                const messageId = message.dataset.messageId;
                const encryptedContent = message.dataset.encryptedContent;
                const fileData = message.dataset.fileData; // Данные файла
                const fileName = message.dataset.fileName; // Имя файла
                const fileSize = message.dataset.fileSize; // Размер файла
                const iv = message.dataset.iv;
                const tag = message.dataset.tag;
                const senderId = message.dataset.senderId;
                const isCurrentUser = senderId === document.body.dataset.currentUserId;
                const isSuspicious = message.dataset.isSuspicious === 'true';

                const messageBlock = message.querySelector('.message-block');
                const messageBubble = message.querySelector('.message-bubble');
                if (!messageBlock || !messageBubble) continue; // Пропускаем, если структура DOM некорректна

                let messageContent = '';
                if ((chatType === 'DM' || chatType === 'GM') && iv && tag) {
                    try {
                        if (fileData && fileName && fileSize) {
                            // Если это сообщение с файлом
                            const fileSizeMB = (parseInt(fileSize) / (1024 * 1024)).toFixed(2);
                            messageContent = `
                                <div class="file-message">
                                    <i class="file-icon bi bi-file-earmark"></i>
                                    <div class="file-info">
                                        <div class="file-name">${fileName}</div>
                                        <div class="file-size">${fileSizeMB} MB</div>
                                    </div>
                                    <a href="#" class="file-download" data-file-data="${fileData}" data-iv="${iv}" data-tag="${tag}" data-file-name="${fileName}">Скачать</a>
                                </div>
                            `;
                        } else if (encryptedContent) {
                            // Если это текстовое сообщение, расшифровываем content
                            const messageText = await decryptMessage(
                                { content: encryptedContent, iv: iv, tag: tag },
                                sessionKey
                            );
                            messageContent = `
                                <div class="message-text">${messageText}</div>
                                ${isSuspicious ? `<div class="suspicious-label text-warning mt-1">Подозрительное сообщение</div>` : ''}
                            `;
                        } else {
                            messageContent = `<div class="message-text">[Пустое сообщение]</div>`;
                        }
                    } catch (e) {
                        console.error('Failed to decrypt initial message for message', messageId, ':', e);
                        messageContent = `<div class="message-text">[Ошибка расшифровки]</div>`;
                    }
                } else {
                    messageContent = `<div class="message-text">${encryptedContent || '[Сообщение не зашифровано]'}</div>`;
                }

                // Обновляем содержимое message-bubble
                const messageUsername = messageBubble.querySelector('.message-username');
                const messageMeta = messageBubble.querySelector('.message-meta');
                messageBubble.innerHTML = '';
                if (messageUsername) {
                    messageBubble.appendChild(messageUsername); // Сохраняем имя пользователя, если есть
                }
                messageBubble.insertAdjacentHTML('beforeend', messageContent);
                if (messageMeta) {
                    messageBubble.appendChild(messageMeta); // Сохраняем метаданные (время, статус)
                }

                if (isSuspicious) {
                    message.classList.add('suspicious-message');
                }

                // Добавляем обработчик для скачивания файла
                const downloadLink = message.querySelector('.file-download');
                if (downloadLink) {
                    downloadLink.addEventListener('click', async (e) => {
                        e.preventDefault();
                        const fileData = downloadLink.dataset.fileData;
                        const iv = downloadLink.dataset.iv;
                        const tag = downloadLink.dataset.tag;
                        const fileName = downloadLink.dataset.fileName;

                        try {
                            const sessionKey = await getSessionKey(chatId);
                            const decryptedFileData = await decryptFileData(
                                { content: fileData, iv: iv, tag: tag },
                                sessionKey
                            );

                            // Создаём Blob и скачиваем файл
                            const blob = new Blob([decryptedFileData], { type: 'application/octet-stream' });
                            const url = window.URL.createObjectURL(blob);
                            const a = document.createElement('a');
                            a.href = url;
                            a.download = fileName;
                            a.click();
                            window.URL.revokeObjectURL(url);
                        } catch (error) {
                            console.error('File decryption error:', error);
                            alert('Ошибка при расшифровке файла: ' + error.message);
                        }
                    });
                }
            }
        }

        function addMessageToChat(data, isCurrentUser, chatType) {
            console.log('Adding message to chat:', { data, isCurrentUser, chatType });
            const messagesContainer = document.querySelector('.messages-container');
            const existingMessage = messagesContainer.querySelector(`.message-row[data-message-id="${data.message_id}"]`);
            if (existingMessage) {
                const messageTextElement = existingMessage.querySelector('.message-text');
                if (messageTextElement) {
                    messageTextElement.textContent = data.message;
                }
                const readStatusElement = existingMessage.querySelector('.read-status');
                if (readStatusElement) {
                    readStatusElement.textContent = data.is_read ? '✓✓' : '✓';
                }
                return;
            }

            const messageClass = isCurrentUser ? 'sent' : 'received';
            const senderInitial = data.sender ? data.sender.charAt(0).toUpperCase() : 'U';
            const suspiciousClass = data.is_suspicious ? 'suspicious-message' : '';

            let messageContent = '';
            if (data.file_name && data.file_data && data.iv && data.tag) {
                const fileSizeMB = (data.file_size / (1024 * 1024)).toFixed(2);
                messageContent = `
                    <div class="file-message">
                        <i class="file-icon bi bi-file-earmark"></i>
                        <div class="file-info">
                            <div class="file-name">${data.file_name}</div>
                            <div class="file-size">${fileSizeMB} MB</div>
                        </div>
                        <a href="#" class="file-download" data-file-data="${data.file_data}" data-iv="${data.iv}" data-tag="${data.tag}" data-file-name="${data.file_name}">Скачать</a>
                    </div>
                `;
            } else {
                messageContent = `
                    <div class="message-text">${data.message}</div>
                    ${data.is_suspicious ? `<div class="suspicious-label text-warning mt-1">Подозрительное сообщение</div>` : ''}
                `;
            }

            const messageElement = `
                <div class="message-row ${messageClass} ${suspiciousClass}" data-message-id="${data.message_id}" data-sender-id="${data.sender_id}" data-is-suspicious="${data.is_suspicious}">
                    ${!isCurrentUser ? `
                    <div class="message-avatar">
                        <div class="user-avatar">${senderInitial}</div>
                    </div>
                    ` : ''}

                    <div class="message-block">
                        <div class="message-bubble">
                            ${!isCurrentUser && chatType === 'GM' ? `
                            <div class="message-username">${data.sender}</div>
                            ` : ''}

                            ${messageContent}

                            <div class="message-meta">
                                <span class="message-time">
                                    ${new Date(data.timestamp).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}
                                </span>
                                ${isCurrentUser ? `
                                <span class="read-status">
                                    ✓${data.is_read ? '✓' : ''}
                                </span>
                                ` : ''}
                            </div>
                        </div>
                    </div>
                </div>
            `;

            messagesContainer.insertAdjacentHTML('beforeend', messageElement);
            messagesContainer.scrollTop = messagesContainer.scrollHeight;

            // Добавляем обработчик для скачивания файла
            const downloadLink = messagesContainer.querySelector(`.message-row[data-message-id="${data.message_id}"] .file-download`);
            if (downloadLink) {
                downloadLink.addEventListener('click', async (e) => {
                    e.preventDefault();
                    const fileData = downloadLink.dataset.fileData;
                    const iv = downloadLink.dataset.iv;
                    const tag = downloadLink.dataset.tag;
                    const fileName = downloadLink.dataset.fileName;

                    try {
                        const chatHeader = document.querySelector('.chat-header');
                        const chatId = chatHeader.dataset.chatId;
                        const sessionKey = await getSessionKey(chatId);

                        // Расшифровываем файл
                        const decryptedFileData = await decryptFileData(
                            { content: fileData, iv: iv, tag: tag },
                            sessionKey
                        );

                        // Создаём Blob и скачиваем файл
                        const blob = new Blob([decryptedFileData], { type: 'application/octet-stream' });
                        const url = window.URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = fileName;
                        a.click();
                        window.URL.revokeObjectURL(url);
                    } catch (error) {
                        console.error('File decryption error:', error);
                        alert('Ошибка при расшифровке файла: ' + error.message);
                    }
                });
            }
        }
    }

    function initUI() {
        const menuBtn = document.getElementById('chatMenuBtn');
        const dropdown = document.getElementById('chatDropdown');

        if (menuBtn && dropdown) {
            menuBtn.addEventListener('click', function(e) {
                e.stopPropagation();
                dropdown.classList.toggle('show');
            });

            document.addEventListener('click', function() {
                dropdown.classList.remove('show');
            });

            dropdown.addEventListener('click', function(e) {
                e.stopPropagation();
            });
        }

        if (document.getElementById('chatInfoModal')) {
            console.log('Found chatInfoModal, initializing modal listener');
            const modalElement = document.getElementById('chatInfoModal');
            const modal = new bootstrap.Modal(modalElement);
            modalElement.addEventListener('shown.bs.modal', function() {
                // Проверяем наличие выпадающего меню в .chat-menu
                const dropdown = document.querySelector('.chat-menu .dropdown-menu');
                if (dropdown) {
                    dropdown.classList.remove('show');
                    console.log('Dropdown menu hidden');
                } else {
                    console.warn('Dropdown menu (.chat-menu .dropdown-menu) not found');
                }
                // Загрузка статуса пользователя для DM чата
                const chatHeader = document.querySelector('.chat-header');
                if (!chatHeader) {
                    console.error('Chat header not found');
                    const statusElement = document.getElementById('userStatus');
                    if (statusElement) {
                        statusElement.textContent = 'Ошибка: Заголовок чата отсутствует';
                    }
                    return;
                }
                const chatType = chatHeader.dataset.chatType;
                console.log('Chat type:', chatType);
                if (chatType !== 'DM') {
                    console.log('Not a DM chat, skipping status fetch');
                    const statusElement = document.getElementById('userStatus');
                    if (statusElement) {
                        statusElement.textContent = 'Статус доступен только для личных чатов';
                    }
                    return;
                }
                let recipientId = chatHeader.dataset.recipientId;
                // Резервный способ получения recipientId
                if (!recipientId) {
                    console.warn('recipientId not found in chatHeader.dataset, trying script tag');
                    const recipientIdScript = document.getElementById('recipientId');
                    if (recipientIdScript) {
                        try {
                            recipientId = JSON.parse(recipientIdScript.textContent);
                            console.log('recipientId from script tag:', recipientId);
                        } catch (e) {
                            console.error('Failed to parse recipientId from script tag:', e);
                        }
                    }
                }
                console.log('Recipient ID:', recipientId);
                if (!recipientId) {
                    console.error('Recipient ID is missing');
                    const statusElement = document.getElementById('userStatus');
                    if (statusElement) {
                        statusElement.textContent = 'Ошибка: ID пользователя отсутствует';
                    }
                    return;
                }
                console.log('Fetching user status for recipientId:', recipientId);
                fetch(`/chat/get-user-status/${recipientId}/`, {
                    method: 'GET',
                    headers: {
                        'Accept': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest',
                        'X-CSRFToken': getCookie('csrftoken')
                    },
                    credentials: 'include'
                })
                    .then(response => {
                        console.log('User status response:', { status: response.status, ok: response.ok });
                        if (!response.ok) {
                            throw new Error(`HTTP error: ${response.status}`);
                        }
                        return response.json();
                    })
                    .then(data => {
                        console.log('User status data:', data);
                        const statusElement = document.getElementById('userStatus');
                        if (!statusElement) {
                            console.error('userStatus element not found');
                            return;
                        }
                        if (data.status === 'success') {
                            statusElement.textContent = data.last_seen === 'recently'
                                ? 'Был в сети недавно'
                                : `Был(а) в сети ${data.last_seen}`;
                        } else {
                            statusElement.textContent = `Ошибка: ${data.message || 'Неизвестная ошибка'}`;
                        }
                    })
                    .catch(error => {
                        console.error('Error fetching user status:', error);
                        const statusElement = document.getElementById('userStatus');
                        if (statusElement) {
                            statusElement.textContent = 'Ошибка загрузки статуса';
                        }
                    });
            });
            // Дополнительная проверка инициализации модала
            modalElement.addEventListener('show.bs.modal', function() {
                console.log('chatInfoModal show event triggered (before shown)');
            });
        }

        const chatNameDisplay = document.getElementById('chatNameDisplay');
        const editNameBtn = document.getElementById('editNameBtn');

        if (chatNameDisplay && editNameBtn) {
            let originalName = chatNameDisplay.textContent;
            let currentInput = null;
            let ignoreBlur = false;

            editNameBtn.addEventListener('click', function() {
                if (currentInput) return;
                startEditing();
            });

            function startEditing() {
                currentInput = document.createElement('input');
                currentInput.type = 'text';
                currentInput.value = originalName;
                currentInput.className = 'form-control form-control-sm d-inline-block w-auto text-center fs-4 border-0 border-bottom';
                currentInput.style.maxWidth = '200px';
                chatNameDisplay.parentNode.replaceChild(currentInput, chatNameDisplay);
                currentInput.focus();
                currentInput.select();
                currentInput.addEventListener('blur', handleBlur);
                currentInput.addEventListener('keydown', handleKeyDown);
            }

            function handleBlur(e) {
                if (ignoreBlur) {
                    ignoreBlur = false;
                    return;
                }
                finishEditing(e.target.value.trim(), false);
            }

            function handleKeyDown(e) {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    ignoreBlur = true;
                    finishEditing(e.target.value.trim(), true);
                } else if (e.key === 'Escape') {
                    e.preventDefault();
                    ignoreBlur = true;
                    revertEditing();
                }
            }

            function finishEditing(newName, fromEnter) {
                if (!currentInput) return;
                currentInput.removeEventListener('blur', handleBlur);
                currentInput.removeEventListener('keydown', handleKeyDown);

                if (newName && newName !== originalName) {
                    saveNewName(newName);
                } else {
                    revertEditing();
                }
            }

            function revertEditing() {
                if (!currentInput || !currentInput.parentNode) return;
                currentInput.parentNode.replaceChild(chatNameDisplay, currentInput);
                currentInput = null;
            }

            function saveNewName(newName) {
                const chatHeader = document.querySelector('.chat-header');
                const chatId = chatHeader.dataset.chatId;
                const csrfToken = chatHeader.dataset.csrfToken;

                fetch(`/chat/rename/${chatId}/`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': csrfToken
                    },
                    body: JSON.stringify({ name: newName })
                })
                .then(response => {
                    if (response.ok) {
                        chatNameDisplay.textContent = newName;
                        originalName = newName;
                    }
                })
                .catch(console.error)
                .finally(() => {
                    if (currentInput && currentInput.parentNode) {
                        currentInput.parentNode.replaceChild(chatNameDisplay, currentInput);
                    }
                    currentInput = null;
                });
            }
        }

        const leaveChatModal = new bootstrap.Modal(document.getElementById('leaveChatModal'));
        const confirmLeaveBtn = document.getElementById('confirmLeaveBtn');
        const leaveChatBtn = document.getElementById('leaveChatBtn');

        if (leaveChatBtn) {
            leaveChatBtn.addEventListener('click', function(e) {
                e.preventDefault();
                e.stopPropagation();
                const dropdown = document.querySelector('.dropdown-menu.show');
                if (dropdown) dropdown.classList.remove('show');
                leaveChatModal.show();
            });
        }

        if (confirmLeaveBtn) {
            confirmLeaveBtn.addEventListener('click', async function() {
                this.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Выход...';
                this.disabled = true;

                try {
                    await leaveChat();
                    leaveChatModal.hide();
                } catch (error) {
                    console.error('Error:', error);
                    alert('Ошибка при выходе из чата: ' + error.message);
                } finally {
                    this.innerHTML = 'Покинуть чат';
                    this.disabled = false;
                }
            });
        }

        async function leaveChat() {
            const chatHeader = document.querySelector('.chat-header');
            const chatId = chatHeader.dataset.chatId;
            const csrfToken = chatHeader.dataset.csrfToken;

            const response = await fetch(`/chat/${chatId}/leave/`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                credentials: 'same-origin'
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            if (!data.success) {
                throw new Error(data.message || 'Не удалось покинуть чат');
            }

            window.location.href = '/chat/';
        }

        const confirmRemoveModal = new bootstrap.Modal(document.getElementById('confirmRemoveModal'));
        let currentUserIdToRemove = null;
        let currentUsernameToRemove = null;

        document.querySelectorAll('.remove-user-btn').forEach(btn => {
            btn.addEventListener('click', function() {
                const userId = this.dataset.userId;
                const username = this.closest('li').querySelector('div:not(.avatar-sm)').textContent.trim();
                currentUserIdToRemove = userId;
                currentUsernameToRemove = username;
                document.getElementById('userToRemoveName').textContent = username;
                confirmRemoveModal.show();
            });
        });

        document.getElementById('confirmRemoveBtn').addEventListener('click', async function() {
            if (!currentUserIdToRemove) return;
            this.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Исключение...';
            this.disabled = true;

            try {
                const chatId = document.querySelector('.chat-header').dataset.chatId;
                const csrfToken = document.querySelector('.chat-header').dataset.csrfToken;
                await removeUserFromChat(chatId, currentUserIdToRemove, csrfToken);
                confirmRemoveModal.hide();
            } catch (error) {
                console.error('Error:', error);
                alert('Ошибка при исключении пользователя: ' + error.message);
            } finally {
                this.innerHTML = 'Исключить';
                this.disabled = false;
            }
        });

        async function removeUserFromChat(chatId, userId, csrfToken) {
            try {
                const response = await fetch(`/chat/${chatId}/remove_user/`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': csrfToken
                    },
                    body: JSON.stringify({ user_id: userId }),
                    credentials: 'same-origin'
                });

                if (!response.ok) throw new Error('Ошибка сервера');
                const data = await response.json();
                if (data.success) {
                    location.reload();
                } else {
                    alert(data.message || 'Не удалось исключить пользователя');
                }
            } catch (error) {
                console.error('Error:', error);
                alert('Произошла ошибка: ' + error.message);
            }
        }

        function updateMessageTimes() {
            document.querySelectorAll('.message-time').forEach(el => {
                // Логика для динамического обновления времени
            });
        }
        setInterval(updateMessageTimes, 60000);

        const reportLinkButton = document.getElementById('reportLinkButton');
        if (reportLinkButton) {
            reportLinkButton.addEventListener('click', async function() {
                const detailsEl = document.getElementById('securityAlertDetails');
                const details = detailsEl.textContent;
                try {
                    const response = await fetch('/chat/report-link/', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-CSRFToken': document.querySelector('.chat-header').dataset.csrfToken,
                            'X-Requested-With': 'XMLHttpRequest'
                        },
                        credentials: 'same-origin',
                        body: JSON.stringify({ details: details })
                    });
                    const data = await response.json();
                    if (data.status === 'success') {
                        alert('Жалоба отправлена. Спасибо за ваш вклад в безопасность!');
                    } else {
                        throw new Error(data.message || 'Не удалось отправить жалобу');
                    }
                    const modal = bootstrap.Modal.getInstance(document.getElementById('securityAlertModal'));
                    modal.hide();
                } catch (error) {
                    console.error('Error reporting link:', error);
                    alert('Ошибка при отправке жалобы: ' + error.message);
                }
            });
        }

        const messageInput = document.getElementById('message-input');
        const fileInput = document.getElementById('file-input');
        if (messageInput && fileInput) {
            messageInput.addEventListener('click', (e) => {
                if (e.offsetX < 40) { // Клик в области иконки (первые 40px)
                    e.preventDefault();
                    fileInput.click();
                    console.log('Triggered file input click via message input icon');
                }
            });
        } else {
            console.error('Message input or file input not found');
        }
    }

    async function init() {
        if (await checkPrivateKey()) {
            await initPhishingDetector();
            chatApp.init();
            initWebSocket();
            initUI();
            await decryptLastMessages();
        }
    }

    init();
});