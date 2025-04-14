document.addEventListener('DOMContentLoaded', function() {
    const chatApp = {
        init() {
            this.cacheElements();
            this.bindEvents();
            console.log('Chat app initialized');
        },

        cacheElements() {
            this.modal = document.getElementById('createChatModal');
            this.userSearch = document.getElementById('userSearch');
            this.userList = document.getElementById('userList');
            this.createBtn = document.getElementById('confirmCreate');
            // Better way to get CSRF token
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
                    credentials: 'include', // Important for cookies
                    body: JSON.stringify({
                        users: selectedUsers
                    })
                });

                // First check if response is OK
                if (!response.ok) {
                    // Try to parse error response as JSON, fallback to text
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
    function updateMessageTimes() {
        document.querySelectorAll('.message-time').forEach(el => {
            // Логика для динамического обновления
            // Например, "1 мин назад" → "2 мин назад"
        });
    }

    const chatMenuBtn = document.getElementById('chatMenuBtn');
    const chatDropdown = document.getElementById('chatDropdown');

    if (chatMenuBtn && chatDropdown) {
        // Обработчики для меню
        chatMenuBtn.addEventListener('click', toggleChatMenu);

        // Обработчики для пунктов меню
        document.querySelectorAll('.rename-chat-btn').forEach(btn => {
            btn.addEventListener('click', renameChat);
        });

        // Добавьте обработчики для других кнопок...
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
                body: JSON.stringify({name: newName})
            })
            .then(response => {
                if (response.ok) {
                    return response.json();
                }
                throw new Error('Ошибка сервера');
            })
            .then(data => {
                if (data.status === 'success') {
                    location.reload(); // Обновляем страницу для отображения нового имени
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

    // Закрытие меню при клике вне его
    document.addEventListener('click', function() {
        if (chatDropdown) chatDropdown.classList.remove('show');
    });

    // Обновлять каждую минуту
    setInterval(updateMessageTimes, 60000);
    chatApp.init();
});

document.addEventListener('DOMContentLoaded', function() {
  // Инициализация меню чата
  const menuBtn = document.getElementById('chatMenuBtn');
  const dropdown = document.getElementById('chatDropdown');

  if (menuBtn && dropdown) {
    menuBtn.addEventListener('click', function(e) {
      e.stopPropagation();
      dropdown.classList.toggle('show');
    });

    // Закрытие при клике вне меню
    document.addEventListener('click', function() {
      dropdown.classList.remove('show');
    });

    // Предотвращаем закрытие при клике внутри меню
    dropdown.addEventListener('click', function(e) {
      e.stopPropagation();
    });
  }

  // Инициализация модального окна через Bootstrap
  if (document.getElementById('chatInfoModal')) {
    const modal = new bootstrap.Modal(document.getElementById('chatInfoModal'));

    // Можно добавить дополнительные обработчики для модального окна
    document.getElementById('chatInfoModal').addEventListener('shown.bs.modal', function() {
      // Действия после открытия модалки
      dropdown.classList.remove('show');
    });
  }


});

document.addEventListener('DOMContentLoaded', function() {
  const chatNameDisplay = document.getElementById('chatNameDisplay');
  const editNameBtn = document.getElementById('editNameBtn');

  if (chatNameDisplay && editNameBtn) {
    let originalName = chatNameDisplay.textContent;
    let currentInput = null;
    let ignoreBlur = false; // Флаг для игнорирования blur после Enter

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

      // Заменяем через родителя для надежности
      chatNameDisplay.parentNode.replaceChild(currentInput, chatNameDisplay);
      currentInput.focus();
      currentInput.select();

      // Обработчики
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
        ignoreBlur = true; // Игнорируем последующий blur
        finishEditing(e.target.value.trim(), true);
      } else if (e.key === 'Escape') {
        e.preventDefault();
        ignoreBlur = true;
        revertEditing();
      }
    }

    function finishEditing(newName, fromEnter) {
      if (!currentInput) return;

      // Удаляем обработчики сразу
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

      // Возвращаем оригинальный элемент
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

    // Инициализация модального окна
  const leaveChatModal = new bootstrap.Modal(document.getElementById('leaveChatModal'));
  const confirmLeaveBtn = document.getElementById('confirmLeaveBtn');
  const leaveChatBtn = document.getElementById('leaveChatBtn');

  if (leaveChatBtn) {
    leaveChatBtn.addEventListener('click', function(e) {
      e.preventDefault();
      e.stopPropagation();

      // Закрываем меню чата
      const dropdown = document.querySelector('.dropdown-menu.show');
      if (dropdown) dropdown.classList.remove('show');

      // Показываем модальное окно вместо confirm()
      leaveChatModal.show();
    });
  }

  // Обработчик подтверждения выхода
  if (confirmLeaveBtn) {
    confirmLeaveBtn.addEventListener('click', async function() {
      // Показываем индикатор загрузки
      this.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Выход...';
      this.disabled = true;

      try {
        await leaveChat();
        leaveChatModal.hide();
      } catch (error) {
        console.error('Error:', error);
        alert('Ошибка при выходе из чата: ' + error.message);
      } finally {
        // Восстанавливаем кнопку
        this.innerHTML = 'Покинуть чат';
        this.disabled = false;
      }
    });
  }

  // Функция для выхода из чата
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

  // Обработчик для кнопок исключения
  document.querySelectorAll('.remove-user-btn').forEach(btn => {
    btn.addEventListener('click', function() {
      const userId = this.dataset.userId;
      const username = this.closest('li').querySelector('div:not(.avatar-sm)').textContent.trim();

      // Сохраняем данные для использования при подтверждении
      currentUserIdToRemove = userId;
      currentUsernameToRemove = username;

      // Устанавливаем имя пользователя в модальное окно
      document.getElementById('userToRemoveName').textContent = username;

      // Показываем модальное окно
      confirmRemoveModal.show();
    });
  });

  // Обработчик подтверждения исключения
  document.getElementById('confirmRemoveBtn').addEventListener('click', async function() {
    if (!currentUserIdToRemove) return;

    // Показываем индикатор загрузки
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
      // Восстанавливаем кнопку
      this.innerHTML = 'Исключить';
      this.disabled = false;
    }
  });

  // Функция для отправки запроса на сервер
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
        // Обновляем список пользователей
        location.reload(); // или более тонкое обновление через DOM
      } else {
        alert(data.message || 'Не удалось исключить пользователя');
      }
    } catch (error) {
      console.error('Error:', error);
      alert('Произошла ошибка: ' + error.message);
    }
  }
});

document.addEventListener('DOMContentLoaded', function() {
    // Задержка для полной загрузки DOM (можете регулировать время)
    setTimeout(initializeChat, 500);
});


function initializeChat() {
    // 1. Получаем основные обязательные элементы
    const requiredElements = {
        chatHeader: document.querySelector('.chat-header'),
        messageForm: document.getElementById('message-form'),
        messageInput: document.getElementById('message-input'),
        messagesContainer: document.querySelector('.messages-container')
    };

    // 2. Проверяем наличие обязательных элементов
    const missingElements = Object.entries(requiredElements)
        .filter(([_, el]) => !el)
        .map(([name]) => name);

    if (missingElements.length > 0) {
        console.error('Missing required elements:', missingElements);
        return;
    }

    // 3. Получаем необязательные элементы
    const errorNotification = document.getElementById('error-notification');

    // 4. Инициализируем чат
    const chatId = requiredElements.chatHeader.dataset.chatId;
    const currentUser = requiredElements.chatHeader.dataset.currentUser;
    let chatSocket;

    // 5. Подключаем WebSocket
    connectWebSocket();

    // 6. Назначаем обработчики событий
    setupEventListeners();

    // ===== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ =====

    function connectWebSocket() {
        chatSocket = new WebSocket(
            `ws://${window.location.host}/ws/chat/${chatId}/`
        );

        chatSocket.onopen = function() {
            console.log('WebSocket connected');
            hideErrorNotification();
        };

        chatSocket.onerror = function(error) {
            console.error('WebSocket Error:', error);
            showErrorNotification('Ошибка соединения с чатом');
        };

        chatSocket.onclose = function() {
            console.log('WebSocket disconnected');
            setTimeout(connectWebSocket, 2000);
        };

        chatSocket.onmessage = function(e) {
            try {
                const data = JSON.parse(e.data);
                console.log('Received message:', data);

                // Добавляем проверку на свое сообщение
                if (data.sender !== currentUser) {
                    addMessageToChat({
                        message: data.message,
                        sender: data.sender,
                        is_read: data.is_read || false,
                        timestamp: data.timestamp || new Date().toISOString()
                    }, false);
                }
            } catch (error) {
                console.error('Error parsing message:', error);
            }
        };
    }

    function setupEventListeners() {
        requiredElements.messageForm.addEventListener('submit', function(e) {
            e.preventDefault();
            sendMessage();
        });

        requiredElements.messageInput.addEventListener('keydown', function(e) {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                sendMessage();
            }
        });
    }

    function sendMessage() {
        const message = requiredElements.messageInput.value.trim();

        if (!message) return;

        if (chatSocket.readyState !== WebSocket.OPEN) {
            showErrorNotification('Соединение потеряно. Пытаемся переподключиться...');
            return;
        }

        try {
            chatSocket.send(JSON.stringify({
                'message': message,
                'csrf_token': getCSRFToken()
            }));

            addMessageToChat({
                message: message,
                sender: currentUser,
                is_read: false,
                timestamp: new Date().toISOString()
            }, true);

            requiredElements.messageInput.value = '';
        } catch (error) {
            console.error('Send error:', error);
            showErrorNotification('Ошибка отправки сообщения');
        }
    }

    function addMessageToChat(data, isCurrentUser) {
        const messageClass = isCurrentUser ? 'sent' : 'received';
        const chatType = requiredElements.chatHeader.dataset.chatType;
        const messageTime = formatTime(data.timestamp);

        const messageElement = document.createElement('div');
        messageElement.className = `message-row ${messageClass}`;
        messageElement.innerHTML = `
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
                            ${messageTime}
                        </span>
                        ${isCurrentUser ? `
                        <span class="read-status">
                            ✓${data.is_read ? '✓' : ''}
                        </span>
                        ` : ''}
                    </div>
                </div>
            </div>
        `;

        requiredElements.messagesContainer.appendChild(messageElement);
        requiredElements.messagesContainer.scrollTop = requiredElements.messagesContainer.scrollHeight;
    }

    function formatTime(timestamp) {
        const date = new Date(timestamp);
        return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }

    function getCSRFToken() {
        return document.cookie
            .split('; ')
            .find(row => row.startsWith('csrftoken='))
            ?.split('=')[1] || '';
    }

    function showErrorNotification(message) {
        if (errorNotification) {
            errorNotification.textContent = message;
            errorNotification.style.display = 'block';
        } else {
            console.error('Notification:', message);
            // Альтернативное уведомление, например alert или console.error
        }
    }

    function hideErrorNotification() {
        if (errorNotification) {
            errorNotification.style.display = 'none';
        }
    }
}