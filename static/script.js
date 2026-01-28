function validateForm() {
    // Клиентская валидация (пустые поля уже required в HTML, но добавим для пароля)
    var password = document.querySelector('input[name="password"]');
    if (password && password.value.length < 6) {
        alert('Пароль должен быть минимум 6 символов!');
        return false;
    }
    return true;
}