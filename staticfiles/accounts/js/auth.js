$(document).ready(function() {
    // Функция для получения CSRF-токена из куки
    function getCsrfToken() {
        let cookieValue = null;
        if (document.cookie && document.cookie !== '') {
            const cookies = document.cookie.split(';');
            for (let i = 0; i < cookies.length; i++) {
                const cookie = cookies[i].trim();
                if (cookie.substring(0, 10) === 'csrftoken=') {
                    cookieValue = decodeURIComponent(cookie.substring(10));
                    break;
                }
            }
        }
        return cookieValue;
    }

    // Обработка основной формы входа
    $('#loginForm').on('submit', function(e) {
        e.preventDefault();

        $.ajax({
            url: $(this).attr('action'),
            type: 'POST',
            data: $(this).serialize() + '&csrfmiddlewaretoken=' + getCsrfToken(),
            success: function(response) {
                if (response.status === 'code_required') {
                    $('#authModal').modal('show');
                    startCountdown();
                } else if (response.redirect) {
                    window.location.href = response.redirect;
                }
            },
            error: function(xhr) {
                const response = xhr.responseJSON || {};
                const errors = response.errors || { message: 'An unexpected error occurred.' };
                showAlert(errors.message, 'alert');
            }
        });
    });

    // Валидация кода по цифрам
    $('.auth-code-input input').on('input', function() {
        const index = parseInt($(this).data('index'));
        const value = $(this).val();

        if (value.length === 1) {
            if (index < 6) {
                $(this).next().focus();
            }
            updateFullCode();
        }
    });

    $('#submitAuthCode').on('click', function(e) {
        e.preventDefault();

        let enteredCode = '';
        $('.auth-code-input input[data-index]').each(function() {
            enteredCode += $(this).val();
        });

        if (enteredCode.length !== 6) {
            showAlert('Пожалуйста, введите полный код.', 'danger');
            return;
        }

        $.ajax({
            url: verifyAuthUrl, // Убедитесь, что verifyAuthUrl определён
            type: 'POST',
            data: {
                code: enteredCode,
                csrfmiddlewaretoken: getCsrfToken()
            },
            success: function(response) {
                if (response.status === 'success') {
                    window.location.href = response.redirect;
                } else {
                    showAlert(response.message, 'danger');
                }
            },
            error: function(xhr) {
                try {
                    const response = JSON.parse(xhr.responseText);
                    showAlert(response.message || 'Произошла ошибка.', 'danger');
                } catch (e) {
                    showAlert('Не удалось обработать ответ сервера.', 'danger');
                }
            }
        });
    });

    // Отмена входа
    $('#cancelAuthBtn').on('click', function() {
        $('#authModal').modal('hide');
        resetCodeInput();
    });

    // Повторная отправка кода
    $('#resendCodeBtn').on('click', function() {
        $.ajax({
            url: $('#loginForm').attr('action'),
            type: 'POST',
            data: $('#loginForm').serialize() + '&csrfmiddlewaretoken=' + getCsrfToken(),
            success: function(response) {
                if (response.status === 'code_required') {
                    startCountdown();
                    showAlert('Новый код отправлен', 'success');
                }
            },
            error: function(xhr) {
                showAlert('Ошибка при отправке кода.', 'danger');
            }
        });
    });

    function startCountdown() {
        let seconds = 60;
        $('#resendCodeBtn').prop('disabled', true);

        const timer = setInterval(function() {
            seconds--;
            $('#countdown').text(seconds);

            if (seconds <= 0) {
                clearInterval(timer);
                $('#timerText').hide();
                $('#resendCodeBtn').prop('disabled', false);
            }
        }, 1000);
    }

    function updateFullCode() {
        let fullCode = '';
        $('.auth-code-input input').each(function() {
            fullCode += $(this).val();
        });
        $('#fullAuthCode').val(fullCode);
    }

    function resetCodeInput() {
        $('.auth-code-input input').val('');
        $('#fullAuthCode').val('');
    }

    function showAlert(message, type = 'danger') {
        const alertBox = $('#alert-box');
        const alertMessage = $('#alert-message');

        alertBox.removeClass('alert-danger alert-success alert-warning alert-info');
        alertBox.addClass(`alert-${type}`);
        alertMessage.text(message);
        alertBox.show();

        setTimeout(() => {
            alertBox.fadeOut();
        }, 5000);
    }
});