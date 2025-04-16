$(document).ready(function() {
    // Обработка основной формы входа
    $('#loginForm').on('submit', function(e) {
        e.preventDefault();

        $.ajax({
            url: $(this).attr('action'),
            type: 'POST',
            data: $(this).serialize(),
            success: function(response) {
                if (response.status === 'code_required') {
                    $('#authModal').modal('show');
                    startCountdown();
                } else if (response.redirect) {
                    window.location.href = response.redirect;
                }
            },
            error: function(xhr) {
                const errors = xhr.responseJSON.errors;
                // Показать ошибки в форме
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

        console.log(enteredCode);
        if (enteredCode.length !== 6) {
            return;
        }

        $.ajax({
            url: verifyAuthUrl,
            type: 'POST',
            data: {
                code: enteredCode,
                csrfmiddlewaretoken: $('input[name="csrfmiddlewaretoken"]').val()
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
                    if (response.message) {
                        showAlert(response.message, 'danger');  // Покажи красивую ошибку
                    } else {
                        showAlert("Произошла ошибка. Повторите попытку позже.", 'danger');
                    }
                } catch (e) {
                    showAlert("Не удалось обработать ответ сервера.", 'danger');
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
        $.post('{% url "login" %}', $('#loginForm').serialize(), function(response) {
            if (response.status === 'code_required') {
                startCountdown();
                showMessage('Новый код отправлен');
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

    function showError(message) {
        $('#error-message').text(message).show();  // покажи где-нибудь над формой
    }

    function showMessage(message) {
        // Реализация показа сообщения
    }

    function showAlert(message, type = 'danger') {
        const alertBox = $('#alert-box');
        const alertMessage = $('#alert-message');

        alertBox.removeClass('alert-danger alert-success alert-warning alert-info');
        alertBox.addClass(`alert-${type}`);
        alertMessage.text(message);

        alertBox.show();

        // Автоматически скрыть через 5 секунд
        setTimeout(() => {
            alertBox.fadeOut();
        }, 5000);
    }
});


