document.addEventListener('DOMContentLoaded', () => {
    const container = document.getElementById('container');
    const registerBtn = document.getElementById('register');
    const loginBtn = document.getElementById('login');

    if (registerBtn && container) {
        registerBtn.addEventListener('click', () => {
            container.classList.add("active");
            clearNotice();
        });
    }

    if (loginBtn && container) {
        loginBtn.addEventListener('click', () => {
            container.classList.remove("active");
            clearNotice();
        });
    }

    const signUpForm = document.querySelector('.sign-up form');
    const signInForm = document.querySelector('.sign-in form');

    // API Configuration
    const API_BASE_URL = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
        ? 'http://localhost:8000/api/auth'
        : '/api/auth';

    // UI Toast Notification Helper
    function showNotice(message, isError = false) {
        let noticeBox = document.getElementById('auth-notice');
        if (!noticeBox) {
            noticeBox = document.createElement('div');
            noticeBox.id = 'auth-notice';
            noticeBox.style.cssText = `
                position: fixed;
                top: 20px;
                left: 50%;
                transform: translateX(-50%);
                padding: 12px 24px;
                border-radius: 8px;
                font-size: 14px;
                font-weight: 500;
                z-index: 9999;
                box-shadow: 0 4px 16px rgba(0,0,0,0.2);
                transition: opacity 0.3s ease;
            `;
            document.body.appendChild(noticeBox);
        }
        noticeBox.style.display = 'block';
        noticeBox.style.backgroundColor = isError ? '#ffebee' : '#e8f5e9';
        noticeBox.style.color = isError ? '#c62828' : '#2e7d32';
        noticeBox.style.border = `1px solid ${isError ? '#ef9a9a' : '#a5d6a7'}`;
        noticeBox.textContent = message;

        setTimeout(() => {
            if (noticeBox) noticeBox.style.display = 'none';
        }, 5000);
    }

    function clearNotice() {
        const noticeBox = document.getElementById('auth-notice');
        if (noticeBox) noticeBox.style.display = 'none';
    }

    // Password Validation Rules
    function checkPasswordComplexity(password) {
        if (password.length < 8) return "Password must be at least 8 characters long.";
        if (!/[A-Z]/.test(password)) return "Password must contain at least one uppercase letter.";
        if (!/[a-z]/.test(password)) return "Password must contain at least one lowercase letter.";
        if (!/\d/.test(password)) return "Password must contain at least one numeric digit.";
        if (!/[!@#$%^&*(),.?":{}|<>\-_+=~`\[\]]/.test(password)) return "Password must contain at least one special character.";
        return null;
    }

    // 1. Handle Registration (Sign Up)
    if (signUpForm) {
        signUpForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            clearNotice();

            const nameInput = signUpForm.querySelector('input[placeholder="Name"]');
            const emailInput = signUpForm.querySelector('input[type="email"]');
            const passwordInput = signUpForm.querySelector('input[type="password"]');
            const submitBtn = signUpForm.querySelector('button[type="submit"]');

            const name = nameInput ? nameInput.value.trim() : '';
            const email = emailInput ? emailInput.value.trim() : '';
            const password = passwordInput ? passwordInput.value : '';

            if (!name || !email || !password) {
                showNotice("Please fill in all registration fields.", true);
                return;
            }

            const pwError = checkPasswordComplexity(password);
            if (pwError) {
                showNotice(pwError, true);
                return;
            }

            submitBtn.disabled = true;
            submitBtn.textContent = "Creating Account...";

            try {
                const response = await fetch(`${API_BASE_URL}/register`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name, email, password })
                });

                const data = await response.json();

                if (response.status === 201) {
                    sessionStorage.setItem('access_token', data.access_token);
                    sessionStorage.setItem('refresh_token', data.refresh_token);
                    sessionStorage.setItem('user', JSON.stringify(data.user));
                    showNotice(`Welcome, ${data.user.name}! Redirecting to store...`, false);
                    setTimeout(() => {
                        window.location.href = 'index.html';
                    }, 1200);
                } else if (response.status === 409) {
                    showNotice("An account with this email address already exists.", true);
                } else if (response.status === 429) {
                    const retryAfter = response.headers.get('Retry-After') || '60';
                    showNotice(`Too many registration attempts. Please wait ${retryAfter}s.`, true);
                } else {
                    showNotice(data.detail || "Registration failed. Please try again.", true);
                }
            } catch (err) {
                showNotice("Unable to connect to authentication server. Please ensure backend is running.", true);
            } finally {
                submitBtn.disabled = false;
                submitBtn.textContent = "Sign Up";
            }
        });
    }

    // 2. Handle Login (Sign In)
    if (signInForm) {
        signInForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            clearNotice();

            const emailInput = signInForm.querySelector('input[type="email"]');
            const passwordInput = signInForm.querySelector('input[type="password"]');
            const submitBtn = signInForm.querySelector('button[type="submit"]');

            const email = emailInput ? emailInput.value.trim() : '';
            const password = passwordInput ? passwordInput.value : '';

            if (!email || !password) {
                showNotice("Email and password are required.", true);
                return;
            }

            submitBtn.disabled = true;
            submitBtn.textContent = "Logging In...";

            try {
                const response = await fetch(`${API_BASE_URL}/login`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, password })
                });

                const data = await response.json();

                if (response.status === 200) {
                    sessionStorage.setItem('access_token', data.access_token);
                    sessionStorage.setItem('refresh_token', data.refresh_token);
                    sessionStorage.setItem('user', JSON.stringify(data.user));
                    showNotice(`Welcome back, ${data.user.name}! Redirecting to store...`, false);
                    setTimeout(() => {
                        window.location.href = 'index.html';
                    }, 1000);
                } else if (response.status === 401) {
                    showNotice("Invalid email or password.", true);
                } else if (response.status === 429) {
                    const retryAfter = response.headers.get('Retry-After') || '60';
                    showNotice(`Rate limit reached: too many login attempts. Please wait ${retryAfter}s.`, true);
                } else {
                    showNotice(data.detail || "Login failed.", true);
                }
            } catch (err) {
                showNotice("Unable to connect to authentication server. Please ensure backend is running.", true);
            } finally {
                submitBtn.disabled = false;
                submitBtn.textContent = "Log In";
            }
        });
    }

    // ==========================================
    // 3. Social OAuth Login Integration
    // ==========================================
    const oauthButtons = document.querySelectorAll('.oauth-btn');
    oauthButtons.forEach(btn => {
        btn.addEventListener('click', async (e) => {
            e.preventDefault();
            const provider = btn.getAttribute('data-provider') || 'google';
            showNotice(`Connecting to ${provider.toUpperCase()}...`, false);

            try {
                // Step 1: Request OAuth URL & CSRF State
                const urlResp = await fetch(`${API_BASE_URL}/oauth/${provider}/url`);
                if (!urlResp.ok) throw new Error("Failed to initialize OAuth handshake");
                const urlData = await urlResp.json();
                const state = urlData.state;

                // Step 2: In web environment, exchange state via callback
                const callbackResp = await fetch(`${API_BASE_URL}/oauth/${provider}/callback`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        state: state,
                        mock_profile: {
                            name: `${provider.charAt(0).toUpperCase() + provider.slice(1)} Verified User`,
                            email: `${provider}.user@stationaryhub.com`,
                            id: `oauth_${Date.now()}`
                        }
                    })
                });

                const data = await callbackResp.json();
                if (callbackResp.ok) {
                    sessionStorage.setItem('access_token', data.access_token);
                    sessionStorage.setItem('refresh_token', data.refresh_token);
                    sessionStorage.setItem('user', JSON.stringify(data.user));
                    showNotice(`Authenticated successfully with ${provider.toUpperCase()}! Redirecting...`, false);
                    setTimeout(() => {
                        window.location.href = 'dashboard.html';
                    }, 1000);
                } else {
                    showNotice(data.detail || "Social authentication failed.", true);
                }
            } catch (err) {
                showNotice(`Social login error with ${provider}: ${err.message}`, true);
            }
        });
    });

    // ==========================================
    // 4. Forgot Password Modal Workflow
    // ==========================================
    const forgotLink = document.getElementById('forgot-password-link');
    const forgotModal = document.getElementById('forgot-modal');
    const closeForgotModal = document.getElementById('close-forgot-modal');
    const step1Div = document.getElementById('forgot-step-1');
    const step2Div = document.getElementById('forgot-step-2');
    const forgotRequestForm = document.getElementById('forgot-request-form');
    const forgotResetForm = document.getElementById('forgot-reset-form');

    if (forgotLink && forgotModal) {
        forgotLink.addEventListener('click', (e) => {
            e.preventDefault();
            forgotModal.style.display = 'flex';
            if (step1Div) step1Div.style.display = 'block';
            if (step2Div) step2Div.style.display = 'none';
        });
    }

    if (closeForgotModal && forgotModal) {
        closeForgotModal.addEventListener('click', () => {
            forgotModal.style.display = 'none';
        });
    }

    // Close on click outside modal box
    if (forgotModal) {
        forgotModal.addEventListener('click', (e) => {
            if (e.target === forgotModal) {
                forgotModal.style.display = 'none';
            }
        });
    }

    // Step 1: Submit email to request token
    if (forgotRequestForm) {
        forgotRequestForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const emailInput = document.getElementById('forgot-email');
            const email = emailInput ? emailInput.value.trim() : '';
            if (!email) return;

            const submitBtn = forgotRequestForm.querySelector('button[type="submit"]');
            submitBtn.disabled = true;
            submitBtn.textContent = "Requesting Token...";

            try {
                const response = await fetch(`${API_BASE_URL}/forgot-password`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email })
                });

                const data = await response.json();
                if (response.ok) {
                    showNotice(data.message, false);
                    step1Div.style.display = 'none';
                    step2Div.style.display = 'block';
                    if (data.reset_token) {
                        const tokenInput = document.getElementById('reset-token-input');
                        if (tokenInput) tokenInput.value = data.reset_token;
                    }
                } else if (response.status === 429) {
                    showNotice("Too many reset attempts. Please wait a minute.", true);
                } else {
                    showNotice(data.detail || "Unable to request password reset.", true);
                }
            } catch (err) {
                showNotice("Network error requesting password reset.", true);
            } finally {
                submitBtn.disabled = false;
                submitBtn.textContent = "Send Recovery Token";
            }
        });
    }

    // Step 2: Submit token and new password
    if (forgotResetForm) {
        forgotResetForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const tokenInput = document.getElementById('reset-token-input');
            const newPwInput = document.getElementById('reset-password-input');
            const confirmPwInput = document.getElementById('reset-confirm-password');

            const token = tokenInput ? tokenInput.value.trim() : '';
            const newPassword = newPwInput ? newPwInput.value : '';
            const confirmPassword = confirmPwInput ? confirmPwInput.value : '';

            if (newPassword !== confirmPassword) {
                showNotice("Passwords do not match.", true);
                return;
            }

            const pwErr = checkPasswordComplexity(newPassword);
            if (pwErr) {
                showNotice(pwErr, true);
                return;
            }

            const submitBtn = forgotResetForm.querySelector('button[type="submit"]');
            submitBtn.disabled = true;
            submitBtn.textContent = "Updating Password...";

            try {
                const response = await fetch(`${API_BASE_URL}/reset-password`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ token, new_password: newPassword })
                });

                const data = await response.json();
                if (response.ok) {
                    showNotice("Password reset successfully! Please log in.", false);
                    forgotModal.style.display = 'none';
                    if (container) container.classList.remove("active");
                } else {
                    showNotice(data.detail || "Password reset failed.", true);
                }
            } catch (err) {
                showNotice("Network error resetting password.", true);
            } finally {
                submitBtn.disabled = false;
                submitBtn.textContent = "Set New Password";
            }
        });
    }
});

