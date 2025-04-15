document.addEventListener('DOMContentLoaded', function() {
    // Проверяем, находимся ли мы на странице подтверждения кода
    const isConfirmationPage = document.getElementById('verify-form') !== null;

    // Логика для страницы подтверждения кода
    if (isConfirmationPage) {
        const resendLink = document.getElementById('resend-code-link');
        const timerText = document.getElementById('resend-timer-text');
        const countdownEl = document.getElementById('countdown');

        // Проверяем существование элементов перед работой с ними
        if (resendLink && timerText && countdownEl) {
            let secondsLeft = 60;

            const timer = setInterval(() => {
                secondsLeft--;
                countdownEl.textContent = secondsLeft;

                if (secondsLeft <= 0) {
                    clearInterval(timer);
                    timerText.style.display = 'none';
                    resendLink.style.display = 'inline';
                }
            }, 1000);

            resendLink.addEventListener('click', function(e) {
                e.preventDefault();
                handleResendCode(resendLink, timerText, countdownEl);
            });
        }
    }

    // Логика для кнопки "Назад" (работает на всех страницах)
    const backLink = document.querySelector('.registration-container .back-link');
    if (backLink) {
        backLink.addEventListener('click', function(e) {
            if(!confirm('Вернуться к странице входа? Введенные данные будут потеряны.')) {
                e.preventDefault();
            }
        });
    }
});

// Вынесем обработчик в отдельную функцию для чистоты кода
function handleResendCode(resendLink, timerText, countdownEl) {
    const csrfToken = document.querySelector('[name=csrfmiddlewaretoken]').value;
    const email = document.querySelector('input[name="email"]').value;

    resendLink.style.opacity = '0.5';
    resendLink.textContent = 'Отправка...';

    fetch('/accounts/resend-confirmation-code/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrfToken
        },
        body: JSON.stringify({ email: email })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            restartTimer(resendLink, timerText, countdownEl);
            showAlert('Новый код отправлен!', 'success');
        } else {
            showAlert('Ошибка: ' + (data.error || 'Не удалось отправить код'), 'error');
        }
        resetResendLink(resendLink);
    })
    .catch(error => {
        console.error('Error:', error);
        showAlert('Произошла ошибка при запросе нового кода', 'error');
        resetResendLink(resendLink);
    });
}

function restartTimer(resendLink, timerText, countdownEl) {
    let secondsLeft = 60;
    timerText.style.display = 'inline';
    resendLink.style.display = 'none';
    countdownEl.textContent = secondsLeft;

    const newTimer = setInterval(() => {
        secondsLeft--;
        countdownEl.textContent = secondsLeft;

        if (secondsLeft <= 0) {
            clearInterval(newTimer);
            timerText.style.display = 'none';
            resendLink.style.display = 'inline';
        }
    }, 1000);
}

function resetResendLink(resendLink) {
    resendLink.style.opacity = '1';
    resendLink.textContent = 'Отправить код повторно';
}

function showAlert(message, type) {
    // Ваша реализация показа уведомлений
    alert(message); // Временная заглушка
}