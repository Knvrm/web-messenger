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

    chatApp.init();
});