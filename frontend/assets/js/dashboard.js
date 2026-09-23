document.addEventListener('DOMContentLoaded', () => {
    const API_BASE = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
        ? 'http://localhost:8000/api'
        : '/api';

    const token = sessionStorage.getItem('access_token');
    const userStr = sessionStorage.getItem('user');

    // 1. Authentication Guard: Redirect if not logged in
    if (!token || !userStr) {
        window.location.href = 'login.html';
        return;
    }

    let currentUser = {};
    try {
        currentUser = JSON.parse(userStr);
    } catch (e) {
        sessionStorage.clear();
        window.location.href = 'login.html';
        return;
    }

    // UI Toast Notification Helper
    function showToast(message, isError = false) {
        const toast = document.getElementById('dash-toast');
        if (!toast) return;
        toast.style.display = 'block';
        toast.style.background = isError ? 'rgba(239, 68, 68, 0.95)' : 'rgba(16, 185, 129, 0.95)';
        toast.style.color = '#ffffff';
        toast.textContent = message;
        setTimeout(() => {
            toast.style.display = 'none';
        }, 4000);
    }

    // Header & User Init
    const greetingEl = document.getElementById('nav-user-greeting');
    const nameEl = document.getElementById('user-display-name');
    const emailEl = document.getElementById('user-display-email');
    const initialsEl = document.getElementById('user-avatar-initials');

    if (greetingEl) greetingEl.textContent = `Hi, ${currentUser.name}`;
    if (nameEl) nameEl.textContent = currentUser.name;
    if (emailEl) emailEl.textContent = currentUser.email;
    if (initialsEl && currentUser.name) {
        initialsEl.textContent = currentUser.name.charAt(0).toUpperCase();
    }

    // Logout Button
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', () => {
            sessionStorage.clear();
            window.location.href = 'login.html';
        });
    }

    // 2. Tab Navigation
    const tabButtons = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    tabButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const targetId = btn.getAttribute('data-tab');
            tabButtons.forEach(b => b.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));

            btn.classList.add('active');
            const targetContent = document.getElementById(targetId);
            if (targetContent) targetContent.classList.add('active');
        });
    });

    // 3. Fetch User Profile & Stats
    async function loadUserProfile() {
        try {
            const resp = await fetch(`${API_BASE}/user/profile`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (resp.status === 401) {
                sessionStorage.clear();
                window.location.href = 'login.html';
                return;
            }
            if (!resp.ok) throw new Error("Failed to load profile");

            const data = await resp.json();

            // Populate form fields
            const emailInput = document.getElementById('prof-email');
            const nameInput = document.getElementById('prof-name');
            const phoneInput = document.getElementById('prof-phone');
            const addrInput = document.getElementById('prof-address');

            if (emailInput) emailInput.value = data.email || '';
            if (nameInput) nameInput.value = data.name || '';
            if (phoneInput) phoneInput.value = data.phone || '';
            if (addrInput) addrInput.value = data.address || '';

            // Populate stats
            const totalOrdersEl = document.getElementById('stat-total-orders');
            const pendingOrdersEl = document.getElementById('stat-pending-orders');
            const totalSpentEl = document.getElementById('stat-total-spent');

            if (totalOrdersEl) totalOrdersEl.textContent = data.stats.total_orders;
            if (pendingOrdersEl) pendingOrdersEl.textContent = data.stats.pending_orders;
            if (totalSpentEl) totalSpentEl.textContent = `₹${data.stats.total_spent.toFixed(2)}`;

            if (nameEl) nameEl.textContent = data.name;
            if (greetingEl) greetingEl.textContent = `Hi, ${data.name}`;
        } catch (err) {
            console.error(err);
        }
    }

    // 4. Load User Orders
    async function loadUserOrders() {
        const container = document.getElementById('orders-container');
        if (!container) return;

        try {
            const resp = await fetch(`${API_BASE}/user/orders`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (!resp.ok) throw new Error("Failed to load orders");
            const data = await resp.json();
            const orders = data.orders || [];

            if (orders.length === 0) {
                container.innerHTML = `
                    <div style="text-align: center; padding: 48px; background: var(--card-bg); border-radius: 16px; border: 1px dashed var(--border-color);">
                        <i class="fa-solid fa-box-open" style="font-size: 40px; color: var(--text-muted); margin-bottom: 12px;"></i>
                        <h3 style="font-size: 16px; margin-bottom: 6px;">No orders found yet</h3>
                        <p style="color: var(--text-muted); font-size: 13px; margin-bottom: 18px;">Ready to order supplies? Visit our Quick Order tab!</p>
                    </div>
                `;
                return;
            }

            container.innerHTML = orders.map(ord => {
                const statusClass = (ord.status || 'in progress').toLowerCase().replace(' ', '-');
                const canCancel = (ord.status || '').toLowerCase() === 'in progress' || (ord.status || '').toLowerCase() === 'pending';
                const createdDate = ord.created_at ? new Date(ord.created_at).toLocaleDateString(undefined, {
                    year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
                }) : 'Recently';

                return `
                    <div class="order-card" id="order-card-${ord.order_id}">
                        <div class="order-main-info">
                            <div>
                                <div class="order-number">Order #${ord.order_id}</div>
                                <div class="order-date">${createdDate} • ${ord.item_count} items</div>
                            </div>
                            <span class="status-badge ${statusClass}">${ord.status}</span>
                        </div>
                        <div class="order-meta">
                            <div class="order-price">₹${Number(ord.total_price).toFixed(2)}</div>
                            <div class="order-actions">
                                ${canCancel ? `<button class="btn-sm btn-cancel" onclick="cancelOrder(${ord.order_id})">Cancel</button>` : ''}
                                <button class="btn-sm btn-reorder" onclick="reorderItems(${ord.order_id})">Reorder</button>
                            </div>
                        </div>
                    </div>
                `;
            }).join('');
        } catch (err) {
            container.innerHTML = `<p style="color: var(--danger); font-size: 14px;">Error loading orders.</p>`;
        }
    }

    // Window global functions for inline onclick
    window.cancelOrder = async function(orderId) {
        if (!confirm(`Are you sure you want to cancel Order #${orderId}?`)) return;
        try {
            const resp = await fetch(`${API_BASE}/user/orders/${orderId}/cancel`, {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const data = await resp.json();
            if (resp.ok) {
                showToast(data.message, false);
                loadUserOrders();
                loadUserProfile();
            } else {
                showToast(data.detail || "Failed to cancel order.", true);
            }
        } catch (err) {
            showToast("Network error cancelling order.", true);
        }
    };

    window.reorderItems = async function(orderId) {
        try {
            const resp = await fetch(`${API_BASE}/user/orders/${orderId}/reorder`, {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const data = await resp.json();
            if (resp.ok) {
                showToast(data.message, false);
                loadUserOrders();
                loadUserProfile();
            } else {
                showToast(data.detail || "Failed to reorder.", true);
            }
        } catch (err) {
            showToast("Network error placing reorder.", true);
        }
    };

    // 5. Update Personal Profile
    const profileForm = document.getElementById('profile-form');
    if (profileForm) {
        profileForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const name = document.getElementById('prof-name').value.trim();
            const phone = document.getElementById('prof-phone').value.trim();
            const address = document.getElementById('prof-address').value.trim();

            if (!name) {
                showToast("Name cannot be empty.", true);
                return;
            }

            try {
                const resp = await fetch(`${API_BASE}/user/profile`, {
                    method: 'PUT',
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ name, phone, address })
                });

                const data = await resp.json();
                if (resp.ok) {
                    showToast("Profile updated successfully!", false);
                    currentUser.name = name;
                    sessionStorage.setItem('user', JSON.stringify(currentUser));
                    if (nameEl) nameEl.textContent = name;
                    if (greetingEl) greetingEl.textContent = `Hi, ${name}`;
                } else {
                    showToast(data.detail || "Failed to update profile.", true);
                }
            } catch (err) {
                showToast("Network error updating profile.", true);
            }
        });
    }

    // 6. Change Password
    const changePwForm = document.getElementById('change-password-form');
    if (changePwForm) {
        changePwForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const oldPw = document.getElementById('curr-password').value;
            const newPw = document.getElementById('new-password').value;
            const confirmPw = document.getElementById('confirm-new-password').value;

            if (newPw !== confirmPw) {
                showToast("New passwords do not match.", true);
                return;
            }

            try {
                const resp = await fetch(`${API_BASE}/user/change-password`, {
                    method: 'PUT',
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ old_password: oldPw, new_password: newPw })
                });

                const data = await resp.json();
                if (resp.ok) {
                    showToast(data.message, false);
                    changePwForm.reset();
                } else {
                    showToast(data.detail || "Failed to change password.", true);
                }
            } catch (err) {
                showToast("Network error updating password.", true);
            }
        });
    }

    // 7. Revoke All Sessions
    const revokeSessionsBtn = document.getElementById('revoke-sessions-btn');
    if (revokeSessionsBtn) {
        revokeSessionsBtn.addEventListener('click', async () => {
            if (!confirm("Are you sure you want to terminate all active sessions? You may need to log in again.")) return;
            try {
                const resp = await fetch(`${API_BASE}/auth/revoke-all-sessions`, {
                    method: 'POST',
                    headers: { 'Authorization': `Bearer ${token}` }
                });
                const data = await resp.json();
                showToast(data.message || "All sessions terminated.", false);
            } catch (err) {
                showToast("Network error terminating sessions.", true);
            }
        });
    }

    // 8. Place Fast Order Catalog
    const CATALOG = [
        { name: "notebook", label: "Ruled Notebook", price: 40.0 },
        { name: "pen", label: "Ballpoint Pen", price: 10.0 },
        { name: "pencil", label: "Graphite Pencil", price: 5.0 },
        { name: "marker", label: "Permanent Marker", price: 25.0 },
        { name: "highlighter", label: "Fluorescent Highlighter", price: 30.0 },
        { name: "ruler", label: "Steel Ruler 30cm", price: 15.0 },
        { name: "eraser", label: "Soft Eraser", price: 5.0 },
        { name: "sharpener", label: "Steel Sharpener", price: 5.0 },
        { name: "stapler", label: "Office Stapler", price: 50.0 }
    ];

    const catalogContainer = document.getElementById('catalog-picker');
    const orderTotalEl = document.getElementById('quick-order-total');
    const placeOrderBtn = document.getElementById('place-quick-order-btn');

    function calculateCatalogTotal() {
        let total = 0;
        CATALOG.forEach(item => {
            const input = document.getElementById(`qty-${item.name}`);
            const qty = input ? parseInt(input.value) || 0 : 0;
            total += qty * item.price;
        });
        if (orderTotalEl) orderTotalEl.textContent = `₹${total.toFixed(2)}`;
        return total;
    }

    if (catalogContainer) {
        catalogContainer.innerHTML = CATALOG.map(it => `
            <div class="catalog-item">
                <div>
                    <div class="catalog-title">${it.label}</div>
                    <div class="catalog-price">₹${it.price.toFixed(2)}</div>
                </div>
                <div class="catalog-qty-row">
                    <label style="font-size: 12px; color: var(--text-muted);">Qty:</label>
                    <input type="number" class="catalog-qty-input" id="qty-${it.name}" min="0" max="50" value="0">
                </div>
            </div>
        `).join('');

        catalogContainer.addEventListener('input', () => {
            calculateCatalogTotal();
        });
    }

    if (placeOrderBtn) {
        placeOrderBtn.addEventListener('click', async () => {
            const items = [];
            CATALOG.forEach(it => {
                const input = document.getElementById(`qty-${it.name}`);
                const qty = input ? parseInt(input.value) || 0 : 0;
                if (qty > 0) {
                    items.push({ item_name: it.name, quantity: qty });
                }
            });

            if (items.length === 0) {
                showToast("Please select at least one stationery item.", true);
                return;
            }

            placeOrderBtn.disabled = true;
            placeOrderBtn.textContent = "Placing Order...";

            try {
                const resp = await fetch(`${API_BASE}/user/orders`, {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ items })
                });

                const data = await resp.json();
                if (resp.status === 201) {
                    showToast(data.message, false);
                    // Reset inputs
                    CATALOG.forEach(it => {
                        const input = document.getElementById(`qty-${it.name}`);
                        if (input) input.value = 0;
                    });
                    calculateCatalogTotal();
                    // Reload data and switch to orders tab
                    loadUserProfile();
                    loadUserOrders();
                    const ordersTabBtn = document.querySelector('[data-tab="tab-orders"]');
                    if (ordersTabBtn) ordersTabBtn.click();
                } else {
                    showToast(data.detail || "Failed to place order.", true);
                }
            } catch (err) {
                showToast("Network error placing order.", true);
            } finally {
                placeOrderBtn.disabled = false;
                placeOrderBtn.textContent = "Place Order Now";
            }
        });
    }

    // Initial Load
    loadUserProfile();
    loadUserOrders();
});
