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
            console.log('Phishing detector setup completed');
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
            const ciphertext = new Uint8Array(atob(encryptedData.content).split('').map(c => c.charCodeAt(0)));
            const iv = new Uint8Array(atob(encryptedData.iv).split('').map(c => c.charCodeAt(0)));
            const tag = new Uint8Array(atob(encryptedData.tag).split('').map(c => c.charCodeAt(0)));
            const encryptedWithTag = new Uint8Array(ciphertext.length + tag.length);
            encryptedWithTag.set(ciphertext);
            encryptedWithTag.set(tag, ciphertext.length);
            //console.log('Decrypting with:', { ciphertext: Array.from(ciphertext), iv: Array.from(iv), tag: Array.from(tag) });
            const decrypted = await crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: iv,
                    tagLength: 128
                },
                sessionKey,
                encryptedWithTag
            );
            const result = new TextDecoder().decode(decrypted);
            //console.log('Decrypted result:', result);
            return result;
        } catch (e) {
            console.error('Message decryption error:', e);
            throw e;
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
            console.log('select user ' + selectedUsers);
            try {
                const sessionKey = await crypto.subtle.generateKey(
                    { name: 'AES-GCM', length: 256 },
                    true,
                    ['encrypt', 'decrypt']
                );

                const currentUserId = document.body.dataset.currentUserId;
                console.log('current user ' + currentUserId);
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

                if (!response.ok) {
                    const errorData = await response.json();
                    throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
                }

                const data = await response.json();

                if (data.status === 'success' || data.status === 'exists') {
                    const exportedKey = await crypto.subtle.exportKey('raw', sessionKey);
                    sessionStorage.setItem(`chat_${data.chat_id}_sessionKey`, btoa(String.fromCharCode(...new Uint8Array(exportedKey))));
                    window.location.href = `${this.baseUrl}/chat/?chat_id=${data.chat_id}`;
                } else {
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
            const iv = chatItem.dataset.iv;
            const tag = chatItem.dataset.tag;
            const lastMessageElement = chatItem.querySelector('.last-message');
            const chatType = chatItem.dataset.chatType || 'DM';

            if (encryptedContent && iv && tag && lastMessageElement && lastMessageElement.textContent !== 'Нет сообщений') {
                try {
                    const sessionKey = await getSessionKey(chatId);
                    const messageText = await decryptMessage(
                        { content: encryptedContent, iv: iv, tag: tag },
                        sessionKey
                    );
                    //console.log('Decrypted last message for chat', chatId, ':', messageText);
                    lastMessageElement.textContent = messageText.length > 25 ? messageText.substring(0, 22) + '...' : messageText;
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

        const chatSocket = new WebSocket(wsUrl);
        const messageForm = document.getElementById('message-form');
        const messageInput = document.getElementById('message-input');

        chatSocket.onopen = function() {
            console.log('WebSocket connected');
        };

        let isUserRestricted = false;

        chatSocket.onmessage = async function(e) {
            try {
                const data = JSON.parse(e.data);
                if (data.type === 'security_alert') {
                    if (data.alert_type === 'user_restricted') {
                        isUserRestricted = true; // Установить флаг блокировки
                    }
                    showSecurityAlert(data.message, data.details, data.alert_type);
                }
                //console.log('WebSocket message received:', data);
                if (data.type === 'new_message') {
                    let messageText = '[Зашифрованное сообщение]';
                    const isCurrentUser = data.sender_id === parseInt(document.body.dataset.currentUserId);
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
                            //console.log('Decrypted message:', messageText);
                        } catch (e) {
                            console.error('Failed to decrypt message:', e);
                            messageText = '[Ошибка расшифровки]';
                        }
                    }
                    addMessageToChat({ ...data, message: messageText }, isCurrentUser, chatType);
                } else if (data.type === 'history') {
                    const messagesContainer = document.querySelector('.messages-container');
                    messagesContainer.innerHTML = '';
                    for (const msg of data.messages) {
                        const isCurrentUser = msg.sender_id === parseInt(document.body.dataset.currentUserId);
                        let messageText = '[Зашифрованное сообщение]';
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
                                //console.log('Decrypted history message:', messageText);
                            } catch (e) {
                                console.error('Failed to decrypt history message:', e);
                                messageText = '[Ошибка расшифровки]';
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
                                is_suspicious: msg.is_suspicious || false
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

        chatSocket.onerror = function(error) {
            console.error('WebSocket Error:', error);
            showSecurityAlert('Ошибка WebSocket', 'Не удалось установить соединение.', 'error');
        };

        chatSocket.onclose = function() {
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

        async function loadInitialMessages(chatId, sessionKey, chatType) {
            const messages = document.querySelectorAll('.message-row');
            for (const message of messages) {
                const messageId = message.dataset.messageId;
                const encryptedContent = message.dataset.encryptedContent;
                const iv = message.dataset.iv;
                const tag = message.dataset.tag;
                const senderId = message.dataset.senderId;
                const isCurrentUser = senderId === document.body.dataset.currentUserId;
                const isSuspicious = message.dataset.isSuspicious === 'true';

                let messageText = 'Encrypted';
                if ((chatType === 'DM' || chatType === 'GM') && encryptedContent && iv && tag) {
                    try {
                        messageText = await decryptMessage(
                            { content: encryptedContent, iv: iv, tag: tag },
                            sessionKey
                        );
                        //console.log('Decrypted initial message:', messageText);
                    } catch (e) {
                        console.error('Failed to decrypt initial message:', e);
                        messageText = '[Ошибка расшифровки]';
                    }
                }
                const messageTextElement = message.querySelector('.message-text');
                if (messageTextElement) {
                    messageTextElement.textContent = messageText;
                }
                if (isSuspicious) {
                    message.classList.add('suspicious-message');
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

            const messageElement = `
                <div class="message-row ${messageClass} ${suspiciousClass}" data-message-id="${data.message_id}" data-sender-id="${data.sender_id}" data-is-suspicious="${data.is_suspicious}">
                    ${!isCurrentUser ? `
                    <div class="message-avatar">
                        <div class="user-avatar">
                            ${senderInitial}
                        </div>
                    </div>
                    ` : ''}

                    <div class="message-block">
                        <div class="message-bubble">
                            ${!isCurrentUser && chatType === 'GM' ? `
                            <div class="message-username">
                                ${data.sender}
                            </div>
                            ` : ''}

                            <div class="message-text">
                                ${data.message}
                            </div>

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
                            ${data.is_suspicious ? `
                            <div class="suspicious-label text-warning mt-1">
                                Подозрительное сообщение
                            </div>
                            ` : ''}
                        </div>
                    </div>
                </div>
            `;

            messagesContainer.insertAdjacentHTML('beforeend', messageElement);
            messagesContainer.scrollTop = messagesContainer.scrollHeight;
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
            const modal = new bootstrap.Modal(document.getElementById('chatInfoModal'));
            document.getElementById('chatInfoModal').addEventListener('shown.bs.modal', function() {
                dropdown.classList.remove('show');
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