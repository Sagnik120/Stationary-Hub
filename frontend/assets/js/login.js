document.addEventListener('DOMContentLoaded', () => {
    const container = document.getElementById('container');
    const registerBtn = document.getElementById('register');
    const loginBtn = document.getElementById('login');

    if (registerBtn && container) {
        registerBtn.addEventListener('click', () => {
            container.classList.add("active");
        });
    }

    if (loginBtn && container) {
        loginBtn.addEventListener('click', () => {
            container.classList.remove("active");
        });
    }

    const signUpForm = document.querySelector('.sign-up form');
    const signInForm = document.querySelector('.sign-in form');

    function validateForm(event, formType) {
        event.preventDefault();

        const emailInput = event.target.querySelector('input[type="email"]');
        const passwordInput = event.target.querySelector('input[type="password"]');
        const email = emailInput ? emailInput.value.trim() : '';
        const password = passwordInput ? passwordInput.value : '';

        if (!email || !password) {
            alert('Both email and password are required.');
            return false;
        }

        // Password validation: at least one number, one capital letter, and length >= 6
        const passwordRegex = /^(?=.*\d)(?=.*[A-Z]).{6,}$/;
        if (!passwordRegex.test(password)) {
            alert('Password must be at least 6 characters long, including at least one number and one capital letter.');
            return false;
        }

        alert(formType === 'sign-up' ? 'Account created successfully!' : 'Login successful!');
        return true;
    }

    if (signUpForm) {
        signUpForm.addEventListener('submit', (e) => validateForm(e, 'sign-up'));
    }
    if (signInForm) {
        signInForm.addEventListener('submit', (e) => validateForm(e, 'sign-in'));
    }
});
