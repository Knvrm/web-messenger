document.addEventListener('DOMContentLoaded', function() {
    const sidebarToggle = document.getElementById('sidebarToggle');
    const sidebarMenu = document.getElementById('sidebarMenu');

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

    const searchInput = document.querySelector('.search-input');
    const chatItems = document.querySelectorAll('.chat-item');

    searchInput.addEventListener('input', function() {
        const searchTerm = this.value.toLowerCase();

        chatItems.forEach(item => {
            const chatName = item.querySelector('.chat-info h4').textContent.toLowerCase();
            const lastMessage = item.querySelector('.last-message').textContent.toLowerCase();

            if (chatName.includes(searchTerm) || lastMessage.includes(searchTerm)) {
                item.style.display = 'flex';
            } else {
                item.style.display = 'none';
            }
        });
    });

});