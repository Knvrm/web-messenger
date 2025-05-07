const verifyAuthUrl = '/accounts/verify-auth-code/';

document.addEventListener('DOMContentLoaded', function() {

    if (typeof jQuery === 'undefined') {
        console.error('jQuery not loaded');
        return;
    }

    function getCsrfToken() {
        let cookieValue = null;
        const cookies = document.cookie.split(';');
        for (let cookie of cookies) {
            cookie = cookie.trim();
            if (cookie.startsWith('csrftoken=')) {
                cookieValue = decodeURIComponent(cookie.substring(10));
                break;
            }
        }
        //console.log('CSRF token:', cookieValue || 'Not found');
        if (!cookieValue) {
            console.error('CSRF token not found in cookies');
        }
        return cookieValue;
    }

    let loginPassword = null;

    const loginForm = $('#loginForm');
    if (loginForm.length === 0) {
        console.error('Login form not found');
        return;
    }

    loginForm.on('submit', function(e) {
        e.preventDefault();
        //console.log('Login form submit event triggered');
        loginPassword = $('#id_password').val() || $('input[name="password"]').val();
        //console.log('Password saved, length:', loginPassword ? loginPassword.length : 'null');

        const formData = $(this).serialize();
        const csrfToken = getCsrfToken();
        if (!csrfToken) {
            showAlert('CSRF-токен не найден. Пожалуйста, обновите страницу.', 'danger');
            return;
        }

        $.ajax({
            url: $(this).attr('action') || '/accounts/login/',
            type: 'POST',
            data: formData + '&csrfmiddlewaretoken=' + encodeURIComponent(csrfToken),
            success: function(response) {
                console.log('Login response:', response);
                if (response.status === 'code_required') {
                    const authModal = $('#authModal');
                    if (authModal.length === 0) {
                        console.error('Auth modal not found');
                        alert('Модальное окно не найдено. Пожалуйста, обновите страницу.');
                        return;
                    }
                    try {
                        authModal.modal('show');
                    } catch (e) {
                        console.error('Bootstrap modal error:', e);
                        alert('Ошибка открытия модального окна. Проверьте подключение Bootstrap.');
                        return;
                    }
                    startCountdown();
                } else if (response.redirect) {
                    console.log('Redirecting to:', response.redirect);
                    window.location.href = response.redirect;
                } else {
                    console.log('Unexpected response:', response);
                    showAlert('Неизвестный ответ сервера', 'danger');
                }
            },
            error: function(xhr) {
                console.log('Login error:', xhr.status, xhr.responseText);
                const response = xhr.responseJSON || {};
                const errors = response.errors || { message: 'Произошла ошибка.' };
                showAlert(errors.email || errors.password || errors.message || 'Ошибка входа.', 'danger');
            }
        });
    });

    $('.auth-code-input input').on('input', function() {
        const index = parseInt($(this).data('index'));
        const value = $(this).val();
        if (value.length === 1 && index < 6) {
            $(this).next().focus();
        }
        updateFullCode();
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

        //console.log('Submitting auth code:', enteredCode);
        const csrfToken = getCsrfToken();
        if (!csrfToken) {
            showAlert('CSRF-токен не найден. Пожалуйста, обновите страницу.', 'danger');
            return;
        }

        $.ajax({
            url: verifyAuthUrl,
            type: 'POST',
            data: {
                code: enteredCode,
                csrfmiddlewaretoken: csrfToken
            },
            timeout: 10000,
            success: async function(response) {
                //console.log('Auth code response:', response);
                let redirectUrl = '/chat/';
                let debugMessage = 'No debug info';

                window.localStorage.setItem('authDebug', JSON.stringify({
                    response: response,
                    timestamp: new Date().toISOString()
                }));

                if (response.status === 'success') {

                    if (response.private_key && response.key_salt && loginPassword) {
                        try {
                            //console.log('Attempting to decrypt private key');
                            const cleanedPrivateKey = response.private_key.replace(/\s/g, '');
                            //console.log('Private key length:', cleanedPrivateKey.length);

                            const isValidBase64 = (str) => {
                                try {
                                    atob(str);
                                    return true;
                                } catch (e) {
                                    return false;
                                }
                            };

                            if (!isValidBase64(cleanedPrivateKey)) {
                                throw new Error('Invalid Base64 string for private_key');
                            }

                            const salt = new Uint8Array(response.key_salt.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
                            const enc = new TextEncoder();
                            const keyMaterial = await crypto.subtle.importKey(
                                'raw',
                                enc.encode(loginPassword),
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

                            const encryptedKey = new Uint8Array(atob(cleanedPrivateKey).split('').map(c => c.charCodeAt(0)));
                            //console.log('Encrypted key length:', encryptedKey.length);
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
                            sessionStorage.setItem('sessionPrivateKey', window.sessionPrivateKey); // Сохраняем в sessionStorage
                            //debugMessage = `Private key decrypted, length: ${window.sessionPrivateKey.length}, starts with: ${window.sessionPrivateKey.slice(0, 20)}...`;
                            //console.log('Private key decrypted:', window.sessionPrivateKey ? 'Success' : 'Failed');
                        } catch (e) {
                            debugMessage = `Decryption error: ${e.message}`;
                            console.error('Decryption error:', e);
                            showAlert(`Ошибка расшифровки ключа: ${e.message}`, 'danger');
                        }
                    } else {
                        debugMessage = `Missing: private_key=${!!response.private_key}, key_salt=${!!response.key_salt}, password=${!!loginPassword}`;
                        showAlert('Недостаточно данных для расшифровки ключа.', 'danger');
                    }
                    redirectUrl = response.redirect || redirectUrl;
                } else {
                    debugMessage = response.message || 'Unknown error';
                    showAlert(response.message, 'danger');
                }

                //console.log('Debug info:', response.debug || debugMessage);
                window.location.href = redirectUrl; // Немедленный редирект
            },
            error: function(xhr) {
                console.log('Auth code error:', xhr.status, xhr.responseText);
                try {
                    const response = JSON.parse(xhr.responseText);
                    showAlert(response.message || 'Произошла ошибка.', 'danger');
                } catch (e) {
                    showAlert(`Не удалось обработать ответ сервера: ${xhr.statusText}`, 'danger');
                }
            }
        });
    });

    $('#cancelAuthBtn').on('click', function() {
        $('#authModal').modal('hide');
        resetCodeInput();
        loginPassword = null;
    });

    $('#resendCodeBtn').on('click', function() {
        const formData = $('#loginForm').serialize();
        const csrfToken = getCsrfToken();
        if (!csrfToken) {
            showAlert('CSRF-токен не найден. Пожалуйста, обновите страницу.', 'danger');
            return;
        }

        $.ajax({
            url: $('#loginForm').attr('action') || '/accounts/login/',
            type: 'POST',
            data: formData + '&csrfmiddlewaretoken=' + encodeURIComponent(csrfToken),
            success: function(response) {
                if (response.status === 'code_required') {
                    startCountdown();
                    showAlert('Новый код отправлен', 'success');
                }
            },
            error: function(xhr) {
                console.log('Resend code error:', xhr.status, xhr.responseText);
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
        if (alertBox.length === 0) {
            console.error('Alert box not found, showing native alert');
            alert(message);
            return;
        }
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