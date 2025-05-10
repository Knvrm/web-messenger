document.addEventListener('DOMContentLoaded', () => {
    const userSelect = document.getElementById('user-select');
    const blockBtn = document.getElementById('block-btn');
    const blacklistUl = document.getElementById('blacklist');
    const hideLastSeenCheckbox = document.getElementById('hideLastSeen');
    const restrictGroupInvitesCheckbox = document.getElementById('restrictGroupInvites');
    const privacyMessage = document.getElementById('privacyMessage');
    const privacyMessageText = document.getElementById('privacyMessageText');
    const csrfToken = document.querySelector('[name=csrfmiddlewaretoken]').value;

    // Загрузка списка пользователей
    fetch('/chat/get-users/')
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                data.users.forEach(user => {
                    const option = document.createElement('option');
                    option.value = user.id;
                    option.textContent = user.username;
                    userSelect.appendChild(option);
                });
            } else {
                showMessage('Ошибка загрузки пользователей: ' + data.message, 'danger');
            }
        })
        .catch(error => showMessage('Ошибка: ' + error, 'danger'));

    // Загрузка черного списка
    function loadBlacklist() {
        blacklistUl.innerHTML = '';
        fetch('/chat/settings/blacklist/')
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    data.blacklist.forEach(user => {
                        const li = document.createElement('li');
                        li.className = 'list-group-item d-flex justify-content-between align-items-center';
                        li.innerHTML = `
                            ${user.username}
                            <button class="btn btn-sm btn-outline-danger unblock-btn" data-user-id="${user.id}">Разблокировать</button>
                        `;
                        blacklistUl.appendChild(li);
                    });
                } else {
                    showMessage('Ошибка загрузки черного списка: ' + data.message, 'danger');
                }
            })
            .catch(error => showMessage('Ошибка: ' + error, 'danger'));
    }

    // Добавление в черный список
    blockBtn.addEventListener('click', () => {
        const userId = userSelect.value;
        if (!userId) {
            showMessage('Выберите пользователя для блокировки', 'danger');
            return;
        }
        fetch('/chat/settings/blacklist/add/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-CSRFToken': csrfToken
            },
            body: `user_id=${userId}`
        })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    loadBlacklist();
                    userSelect.value = '';
                    showMessage(data.message, 'success');
                } else {
                    showMessage('Ошибка: ' + data.message, 'danger');
                }
            })
            .catch(error => showMessage('Ошибка: ' + error, 'danger'));
    });

    // Удаление из черного списка
    blacklistUl.addEventListener('click', (e) => {
        if (e.target.classList.contains('unblock-btn')) {
            const userId = e.target.dataset.userId;
            fetch('/chat/settings/blacklist/remove/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'X-CSRFToken': csrfToken
                },
                body: `user_id=${userId}`
            })
                .then(response => response.json())
                .then(data => {
                    if (data.status === 'success') {
                        loadBlacklist();
                        showMessage(data.message, 'success');
                    } else {
                        showMessage('Ошибка: ' + data.message, 'danger');
                    }
                })
                .catch(error => showMessage('Ошибка: ' + error, 'danger'));
        }
    });

    // Показ уведомления
    function showMessage(message, type) {
        if (!privacyMessage || !privacyMessageText) return;
        privacyMessageText.textContent = message;
        privacyMessage.className = `alert alert-${type} alert-dismissible fade show`;
        privacyMessage.style.display = 'block';

        // Автоматическое скрытие через 5 секунд
        setTimeout(() => {
            privacyMessage.classList.remove('show');
            setTimeout(() => {
                privacyMessage.style.display = 'none';
            }, 300); // Совпадает с длительностью анимации
        }, 5000);
    }

    // Обновление настроек приватности
    function updatePrivacySettings() {
        const hideLastSeen = hideLastSeenCheckbox.checked;
        const restrictGroupInvites = restrictGroupInvitesCheckbox.checked;

        fetch('/chat/settings/update-privacy/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-CSRFToken': csrfToken
            },
            body: `hide_last_seen=${hideLastSeen}&restrict_group_invites=${restrictGroupInvites}`
        })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    showMessage(data.message, 'success');
                } else {
                    showMessage('Ошибка: ' + data.message, 'danger');
                    // Откатить переключатели
                    hideLastSeenCheckbox.checked = !hideLastSeen;
                    restrictGroupInvitesCheckbox.checked = !restrictGroupInvites;
                }
            })
            .catch(error => {
                showMessage('Ошибка: ' + error, 'danger');
                // Откатить переключатели
                hideLastSeenCheckbox.checked = !hideLastSeen;
                restrictGroupInvitesCheckbox.checked = !restrictGroupInvites;
            });
    }

    hideLastSeenCheckbox.addEventListener('change', updatePrivacySettings);
    restrictGroupInvitesCheckbox.addEventListener('change', updatePrivacySettings);

    // Первоначальная загрузка черного списка
    loadBlacklist();
});