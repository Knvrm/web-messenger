document.addEventListener('DOMContentLoaded', function() {
    console.log('Chat app initialized');

    // --- Проверка и расшифровка приватного ключа ---
    async function checkPrivateKey() {
        console.log('Checking private key availability');
        const sessionPrivateKey = sessionStorage.getItem('sessionPrivateKey');

        if (sessionPrivateKey) {
            window.sessionPrivateKey = sessionPrivateKey;
            console.log('Using private key, length:', sessionPrivateKey.length);
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

    // --- Функции шифрования ---
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
            const decrypted = await crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: iv,
                    tagLength: 128
                },
                sessionKey,
                encryptedWithTag
            );
            return new TextDecoder().decode(decrypted);
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

    const chatHeader = document.querySelector('.chat-header');
    const chatType = chatHeader ? chatHeader.dataset.chatType : null;
    const recipientIdScript = document.getElementById('recipientId');
    const recipientId = recipientIdScript ? JSON.parse(recipientIdScript.textContent) : null;
    console.log('Recipient ID:', recipientId);

    if (chatType === 'DM' && recipientId) {
        chatHeader.dataset.recipientId = recipientId;
    }

    // --- Логика создания чатов (chatApp) ---
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

            // Проверяем, выбран ли хотя бы один другой пользователь
            if (selectedUsers.length < 1) {
                this.showError('Выберите хотя бы одного другого участника');
                return;
            }
            console.log('select user ' + selectedUsers);
            try {
                // Генерируем сессионный ключ
                const sessionKey = await crypto.subtle.generateKey(
                    { name: 'AES-GCM', length: 256 },
                    true,
                    ['encrypt', 'decrypt']
                );

                // Получаем публичные ключи всех участников (включая текущего пользователя)
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

                // Отправляем запрос на создание чата
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
                    // Сохраняем сессионный ключ для нового чата
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

    // --- WebSocket и отправка сообщений ---
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

        // Расшифровываем сообщения, отрендеренные сервером
        await loadInitialMessages(chatId, sessionKey, chatType);

        const chatSocket = new WebSocket(wsUrl);
        const messageForm = document.getElementById('message-form');
        const messageInput = document.getElementById('message-input');

        chatSocket.onopen = function() {
            console.log('WebSocket connected');
        };

        chatSocket.onmessage = async function(e) {
            try {
                const data = JSON.parse(e.data);
                console.log('WebSocket message received:', data);
                if (data.type === 'new_message') {
                    let messageText = data.message;
                    const isCurrentUser = data.sender_id === parseInt(document.body.dataset.currentUserId);
                    if ((chatType === 'DM' || chatType === 'GM') && data.content && data.iv && data.tag) {
                        try {
                            messageText = await decryptMessage(
                                { content: data.content, iv: data.iv, tag: data.tag },
                                sessionKey
                            );
                            console.log('Decrypted message:', messageText);
                        } catch (e) {
                            console.error('Failed to decrypt message:', e);
                            messageText = '[Ошибка расшифровки]';
                        }
                    }
                    addMessageToChat({ ...data, message: messageText }, isCurrentUser, chatType);
                } else if (data.type === 'history') {
                    const messagesContainer = document.querySelector('.messages-container');
                    messagesContainer.innerHTML = ''; // Очищаем контейнер перед добавлением истории
                    for (const msg of data.messages) {
                        const isCurrentUser = msg.sender_id === parseInt(document.body.dataset.currentUserId);
                        let messageText = msg.content;
                        if ((chatType === 'DM' || chatType === 'GM') && msg.content && msg.iv && msg.tag) {
                            try {
                                messageText = await decryptMessage(
                                    { content: msg.content, iv: msg.iv, tag: msg.tag },
                                    sessionKey
                                );
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
                                is_read: msg.is_read
                            },
                            isCurrentUser,
                            chatType
                        );
                    }
                }
            } catch (error) {
                console.error('Error parsing message:', error);
            }
        };

        chatSocket.onerror = function(error) {
            console.error('WebSocket Error:', error);
        };

        chatSocket.onclose = function() {
            console.log('WebSocket disconnected');
        };

        messageForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            const message = messageInput.value.trim();

            if (message && chatSocket.readyState === WebSocket.OPEN) {
                if (chatType === 'DM' || chatType === 'GM') {
                    try {
                        const encryptedData = await encryptMessage(message, sessionKey);
                        console.log('Encrypted data:', encryptedData);
                        chatSocket.send(JSON.stringify({
                            type: 'message',
                            content: encryptedData.content,
                            iv: encryptedData.iv,
                            tag: encryptedData.tag
                        }));
                    } catch (e) {
                        console.error('Encryption failed:', e);
                        alert('Ошибка шифрования сообщения');
                        return;
                    }
                } else {
                    chatSocket.send(JSON.stringify({ type: 'message', content: message }));
                }
                messageInput.value = '';
            }
        });

        async function loadInitialMessages(chatId, sessionKey, chatType) {
            const messages = document.querySelectorAll('.message-row');
            for (const message of messages) {
                const messageId = message.dataset.messageId;
                const encryptedContent = message.dataset.encryptedContent;
                const iv = message.dataset.iv;
                const tag = message.dataset.tag;
                const senderId = message.dataset.senderId;
                const isCurrentUser = senderId === document.body.dataset.currentUserId;

                let messageText = 'Encrypted';
                if ((chatType === 'DM' || chatType === 'GM') && encryptedContent && iv && tag) {
                    try {
                        messageText = await decryptMessage(
                            { content: encryptedContent, iv: iv, tag: tag },
                            sessionKey
                        );
                        console.log('Decrypted initial message:', messageText);
                    } catch (e) {
                        console.error('Failed to decrypt initial message:', e);
                        messageText = '[Ошибка расшифровки]';
                    }
                }
                const messageTextElement = message.querySelector('.message-text');
                if (messageTextElement) {
                    messageTextElement.textContent = messageText;
                }
            }
        }

        function addMessageToChat(data, isCurrentUser, chatType) {
            const messagesContainer = document.querySelector('.messages-container');
            const existingMessage = messagesContainer.querySelector(`.message-row[data-message-id="${data.message_id}"]`);
            if (existingMessage) {
                // Обновляем существующее сообщение
                const messageTextElement = existingMessage.querySelector('.message-text');
                if (messageTextElement) {
                    messageTextElement.textContent = data.message;
                }
                return;
            }

            const messageClass = isCurrentUser ? 'sent' : 'received';
            const senderInitial = data.sender ? data.sender.charAt(0).toUpperCase() : 'U';

            const messageElement = `
                <div class="message-row ${messageClass}" data-message-id="${data.message_id}" data-sender-id="${data.sender_id}">
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
                        </div>
                    </div>
                </div>
            `;

            messagesContainer.insertAdjacentHTML('beforeend', messageElement);
            messagesContainer.scrollTop = messagesContainer.scrollHeight;
        }
    }

    // --- UI: Меню, модалки, переименование ---
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
    }

    // --- Инициализация ---
    async function init() {
        if (await checkPrivateKey()) {
            chatApp.init();
            initWebSocket();
            initUI();
        }
    }

    init();
});