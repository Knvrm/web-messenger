document.addEventListener('DOMContentLoaded', function() {
    console.log('Chat app initialized');

    // --- Проверка и расшифровка ключа ---
    async function checkPrivateKey() {
        console.log('Checking private key availability');
        const sessionPrivateKey = sessionStorage.getItem('sessionPrivateKey');

        console.log('Session private key:', sessionPrivateKey ? 'Exists' : 'Missing');

        if (sessionPrivateKey) {
            // Ключ уже расшифрован, используем его
            window.sessionPrivateKey = sessionPrivateKey;
            console.log('Using private key, length:', sessionPrivateKey.length);
            return true;
        }

        // Ключ отсутствует, запрашиваем private_key и key_salt с сервера
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
                // Сохраняем для использования в #decryptForm
                sessionStorage.setItem('encryptedPrivateKey', data.private_key);
                sessionStorage.setItem('keySalt', data.key_salt);
                // Показываем модальное окно для ввода пароля
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
                // Перезагружаем чат
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
    async function encryptMessage(message, publicKeyPem) {
        try {
            // 1. Генерируем случайный AES-ключ
            const aesKey = await crypto.subtle.generateKey(
                { name: 'AES-GCM', length: 256 },
                true,
                ['encrypt', 'decrypt']
            );

            // 2. Шифруем сообщение AES-GCM
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const enc = new TextEncoder();
            const encrypted = await crypto.subtle.encrypt(
                {
                    name: 'AES-GCM',
                    iv: iv,
                    tagLength: 128
                },
                aesKey,
                enc.encode(message)
            );

            // Разделяем шифртекст и тег
            const ciphertext = encrypted.slice(0, -16);
            const tag = encrypted.slice(-16);

            // 3. Экспортируем AES-ключ
            const exportedAesKey = await crypto.subtle.exportKey('raw', aesKey);

            // 4. Импортируем публичный ключ RSA
            const publicKey = await crypto.subtle.importKey(
                'spki',
                new TextEncoder().encode(publicKeyPem),
                { name: 'RSA-OAEP', hash: 'SHA-256' },
                false,
                ['encrypt']
            );

            // 5. Шифруем AES-ключ с RSA
            const encryptedKey = await crypto.subtle.encrypt(
                { name: 'RSA-OAEP' },
                publicKey,
                exportedAesKey
            );

            // 6. Кодируем в Base64
            return {
                content: btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
                encrypted_key: btoa(String.fromCharCode(...new Uint8Array(encryptedKey))),
                iv: btoa(String.fromCharCode(...iv)),
                tag: btoa(String.fromCharCode(...new Uint8Array(tag)))
            };
        } catch (e) {
            console.error('Encryption error:', e);
            throw e;
        }
    }

    async function decryptMessage(encryptedData, privateKeyPem) {
        try {
            // 1. Декодируем Base64
            const ciphertext = new Uint8Array(atob(encryptedData.content).split('').map(c => c.charCodeAt(0)));
            const encryptedKey = new Uint8Array(atob(encryptedData.encrypted_key).split('').map(c => c.charCodeAt(0)));
            const iv = new Uint8Array(atob(encryptedData.iv).split('').map(c => c.charCodeAt(0)));
            const tag = new Uint8Array(atob(encryptedData.tag).split('').map(c => c.charCodeAt(0)));

            // 2. Импортируем приватный ключ RSA
            const privateKey = await crypto.subtle.importKey(
                'pkcs8',
                new TextEncoder().encode(privateKeyPem),
                { name: 'RSA-OAEP', hash: 'SHA-256' },
                false,
                ['decrypt']
            );

            // 3. Расшифровываем AES-ключ
            const decryptedAesKey = await crypto.subtle.decrypt(
                { name: 'RSA-OAEP' },
                privateKey,
                encryptedKey
            );

            // 4. Импортируем AES-ключ
            const aesKey = await crypto.subtle.importKey(
                'raw',
                decryptedAesKey,
                'AES-GCM',
                false,
                ['decrypt']
            );

            // 5. Объединяем шифртекст и тег
            const encryptedWithTag = new Uint8Array(ciphertext.length + tag.length);
            encryptedWithTag.set(ciphertext);
            encryptedWithTag.set(tag, ciphertext.length);

            // 6. Расшифровываем сообщение
            const decrypted = await crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: iv,
                    tagLength: 128
                },
                aesKey,
                encryptedWithTag
            );

            return new TextDecoder().decode(decrypted);
        } catch (e) {
            console.error('Decryption error:', e);
            throw e;
        }
    }

    // --- Запрос public_key ---
    async function getPublicKey(userId) {
        try {
            const response = await fetch(`/chat/get-public-key/${userId}/`, {
                headers: {
                    'Accept': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                }
            });
            const data = await response.json();
            if (data.status === 'success') {
                return data.public_key;
            } else {
                throw new Error(data.message || 'Failed to fetch public key');
            }
        } catch (e) {
            console.error('Error fetching public key:', e);
            throw e;
        }
    }

    const chatHeader = document.querySelector('.chat-header');
    const chatType = chatHeader ? chatHeader.dataset.chatType : null;
    const recipientIdScript = document.getElementById('recipientId');
    const recipientId = recipientIdScript ? JSON.parse(recipientIdScript.textContent) : null;

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
                const response = await fetch(`${this.baseUrl}${this.getUsersUrl}`, {
                    headers: {
                        'Accept': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                });

                const data = await response.json();

                if (!response.ok || data.status !== 'success') {
                    throw new Error(data.message || 'Ошибка сервера');
                }

                this.renderUsers(data.users);
            } catch (error) {
                console.error('Ошибка загрузки пользователей:', error);
                this.showError(error.message);
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

            if (selectedUsers.length === 0) {
                this.showError('Выберите хотя бы одного участника');
                return;
            }

            try {
                const response = await fetch(`${this.baseUrl}${this.createChatUrl}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': this.csrfToken,
                        'X-Requested-With': 'XMLHttpRequest'
                    },
                    credentials: 'include',
                    body: JSON.stringify({
                        users: selectedUsers
                    })
                });

                if (!response.ok) {
                    try {
                        const errorData = await response.json();
                        throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
                    } catch (e) {
                        const errorText = await response.text();
                        throw new Error(errorText || `HTTP error! status: ${response.status}`);
                    }
                }

                const data = await response.json();

                if (data.status === 'success' || data.status === 'exists') {
                    window.location.href = `${this.baseUrl}/chat/`;
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
    function initWebSocket() {
        const chatHeader = document.querySelector('.chat-header');
        if (!chatHeader) return;

        const chatId = chatHeader.dataset.chatId;
        const chatType = chatHeader.dataset.chatType;
        const recipientId = chatHeader.dataset.recipientId || null;
        const protocol = window.location.protocol === 'https:' ? 'wss://' : 'ws://';
        const wsUrl = `${protocol}mymessenger.local:8444/ws/chat/${chatId}/`;

        const chatSocket = new WebSocket(wsUrl);
        const messageForm = document.getElementById('message-form');
        const messageInput = document.getElementById('message-input');

        chatSocket.onopen = function() {
            console.log('WebSocket connected');
        };

        chatSocket.onmessage = async function(e) {
            try {
                const data = JSON.parse(e.data);
                if (data.type === 'new_message') {
                    let messageText = data.message;
                    if (chatType === 'DM' && data.content && data.encrypted_key && data.iv && data.tag) {
                        // Расшифровка для DM
                        try {
                            messageText = await decryptMessage(
                                {
                                    content: data.content,
                                    encrypted_key: data.encrypted_key,
                                    iv: data.iv,
                                    tag: data.tag
                                },
                                window.sessionPrivateKey
                            );
                        } catch (e) {
                            console.error('Failed to decrypt message:', e);
                            messageText = '[Ошибка расшифровки]';
                        }
                    }
                    addMessageToChat({ ...data, message: messageText }, data.sender === '{{ request.user.username }}');
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
                if (chatType === 'DM' && recipientId) {
                    try {
                        // Получаем public_key получателя
                        const publicKey = await getPublicKey(recipientId);
                        // Шифруем сообщение
                        const encryptedData = await encryptMessage(message, publicKey);
                        chatSocket.send(JSON.stringify({
                            content: encryptedData.content,
                            encrypted_key: encryptedData.encrypted_key,
                            iv: encryptedData.iv,
                            tag: encryptedData.tag
                        }));
                    } catch (e) {
                        console.error('Encryption failed:', e);
                        alert('Ошибка шифрования сообщения');
                        return;
                    }
                } else {
                    // Для GM или без шифрования (временно)
                    chatSocket.send(JSON.stringify({ 'message': message }));
                }
                messageInput.value = '';
            }
        });

        function addMessageToChat(data, isCurrentUser) {
            const messageClass = isCurrentUser ? 'sent' : 'received';
            const chatType = chatHeader.dataset.chatType;

            const messageElement = `
                <div class="message-row ${messageClass}">
                    ${!isCurrentUser && chatType === 'GM' ? `
                    <div class="message-avatar">
                        <div class="user-avatar">
                            ${data.sender.charAt(0).toUpperCase()}
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
                                    ${new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}
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

            const container = document.querySelector('.messages-container');
            container.insertAdjacentHTML('beforeend', messageElement);
            container.scrollTop = container.scrollHeight;
        }
    }

    // --- UI: Меню, модалки, переименование ---
    function initUI() {
        // Меню чата
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

        // Модальное окно chatInfoModal
        if (document.getElementById('chatInfoModal')) {
            const modal = new bootstrap.Modal(document.getElementById('chatInfoModal'));
            document.getElementById('chatInfoModal').addEventListener('shown.bs.modal', function() {
                dropdown.classList.remove('show');
            });
        }

        // Переименование чата
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

        // Модальное окно для выхода из чата
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

        // Удаление участников
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

        // Таймер для обновления времени сообщений
        function updateMessageTimes() {
            document.querySelectorAll('.message-time').forEach(el => {
                // Логика для динамического обновления
                // Например, "1 мин назад" → "2 мин назад"
            });
        }
        setInterval(updateMessageTimes, 60000);

        // Старая логика меню чата (для совместимости)
        const chatMenuBtn = document.getElementById('chatMenuBtn');
        const chatDropdown = document.getElementById('chatDropdown');

        if (chatMenuBtn && chatDropdown) {
            chatMenuBtn.addEventListener('click', toggleChatMenu);
            document.querySelectorAll('.rename-chat-btn').forEach(btn => {
                btn.addEventListener('click', renameChat);
            });
        }

        function toggleChatMenu(e) {
            e.stopPropagation();
            chatDropdown.classList.toggle('show');
        }

        function renameChat(e) {
            e.preventDefault();
            const chatHeader = document.querySelector('.chat-header');
            if (!chatHeader) return;
            const chatId = chatHeader.dataset.chatId;
            const chatName = chatHeader.dataset.chatName;
            const csrfToken = chatHeader.dataset.csrfToken;
            const newName = prompt("Введите новое название чата:", chatName);
            if (newName && newName !== chatName) {
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
                        return response.json();
                    }
                    throw new Error('Ошибка сервера');
                })
                .then(data => {
                    if (data.status === 'success') {
                        location.reload();
                    } else {
                        alert(data.message || 'Ошибка при переименовании');
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert('Ошибка при переименовании чата');
                });
            }
        }
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