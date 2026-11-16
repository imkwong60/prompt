/**
 * 提示本本 – Secure local AI prompt notebook
 * AES-GCM + PBKDF2 (120k iterations) · Offline-first · Supabase Auth + E2EE sync
 */
const CRYPTO = {
  PBKDF2_ITERATIONS: 120_000,
  SALT_BYTES: 16,
  IV_BYTES: 12,
  KEY_BITS: 256,
};
const DEFAULT_CATEGORIES = ['寫程式', 'Database', '角色人設', 'UI 規格', '其他'];

const SUPABASE_URL = 'https://wanknivxcsrasdkkxmfr.supabase.co';
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6IndhbmtuaXZ4Y3NyYXNka2t4bWZyIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODczMzE4NjcsImV4cCI6MjEwMjkwNzg2N30.tqsFimERtYCxoh8J-8FlqxByWtX2gNnyaGo08jditrs';
const APP_NAME = 'promptbook';

function promptNotebook() {
  return {
    // ── State ──────────────────────────────────────────────
    prompts: [],
    categories: [...DEFAULT_CATEGORIES],
    categoryDialogOpen: false,
    categoryDrafts: [],
    searchQuery: '',
    isModalOpen: false,
    editingId: null,
    formData: { title: '', category: '', tags: '', prompt: '', notes: '' },
    toasts: [],
    isOnline: navigator.onLine,
    isUnlocked: false,
    isLocked: true,
    hasMasterPassword: false,
    isFirstSetup: false,
    masterPasswordInput: '',
    confirmPasswordInput: '',
    unlockError: '',
    isProcessing: false,
    showMasterPassword: false,
    darkMode: false,
    // Import dialog
    importDialogOpen: false,
    importPreview: [],
    importPreviewCategories: [],
    // Cloud sync / Auth
    syncDialogOpen: false,
    authEmail: '',
    authPassword: '',
    authError: '',
    authUser: null,
    authLoading: false,
    isSyncing: false,
    lastSyncedAt: null,
    remoteUpdatedAt: null,
    showAuthPassword: false,
    _cryptoKey: null,
    _salt: null,
    _supabase: null,

    // ── Computed ───────────────────────────────────────────
    get filteredPrompts() {
      const q = (this.searchQuery || '').trim().toLowerCase();
      if (!q) return this.prompts;
      return this.prompts.filter(p =>
        (p.title || '').toLowerCase().includes(q) ||
        (p.category || '').toLowerCase().includes(q) ||
        (p.tags || '').toLowerCase().includes(q) ||
        (p.prompt || '').toLowerCase().includes(q) ||
        (p.notes || '').toLowerCase().includes(q)
      );
    },

    get isLoggedIn() {
      return !!(this.authUser && this.authUser.id);
    },

    // ── Lifecycle ──────────────────────────────────────────
    async init() {
      this._loadTheme();
      window.addEventListener('online', () => this.isOnline = true);
      window.addEventListener('offline', () => this.isOnline = false);
      window.addEventListener('storage', (e) => {
        // 僅在本分頁尚未鎖定時回應，避免 lock() setItem 造成跨 tab 無限 ping-pong
        if (e.key === 'promptbook_lock_signal' && e.newValue && !this.isLocked) {
          this.lock();
        }
      });
      // Lock on page hide / visibility change for better security
      document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'hidden' && this.isUnlocked) {
          // Soft lock on background is optional; full lock on unload
        }
      });
      this._initSupabase();
      await this._bootstrap();
      localStorage.removeItem('promptbook_supabase_session');
      localStorage.removeItem('promptbook_pkce_verifier');
    },

    _initSupabase() {
      try {
        if (typeof supabase !== 'undefined' && supabase.createClient) {
          this._supabase = supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
            auth: {
              persistSession: true,
              autoRefreshToken: true,
              detectSessionInUrl: true,
              storageKey: 'promptbook_sb_auth',
            },
          });
          this._supabase.auth.onAuthStateChange((event, session) => {
            this.authUser = session?.user ?? null;
            if (event === 'SIGNED_OUT') {
              this.lastSyncedAt = null;
              this.remoteUpdatedAt = null;
            }
          });
          // Restore session
          this._supabase.auth.getSession().then(({ data }) => {
            this.authUser = data?.session?.user ?? null;
          }).catch(() => {});
        } else {
          console.warn('[提示本本] supabase-js 未載入，雲端同步不可用');
        }
      } catch (e) {
        console.error('[提示本本] Supabase 初始化失敗', e);
      }
    },

    async _bootstrap() {
      const meta = this._readMeta();
      const encrypted = localStorage.getItem('promptbook_vault');

      if (encrypted && meta?.salt) {
        this.hasMasterPassword = true;
        this.isLocked = true;
        this.isUnlocked = false;
        this.isFirstSetup = false;
      } else {
        // Prompt data has its own storage namespace; existing Sharebook data remains untouched.
        this.hasMasterPassword = false;
        this.isFirstSetup = true;
        this.isLocked = true;
        this.isUnlocked = false;
        this.prompts = [];
      }
    },

    // ── Theme ──────────────────────────────────────────────
    _loadTheme() {
      const saved = localStorage.getItem('sharebook_theme');
      if (saved === 'dark') this.darkMode = true;
      else if (saved === 'light') this.darkMode = false;
      else this.darkMode = window.matchMedia('(prefers-color-scheme: dark)').matches;
      this._applyTheme();
    },
    toggleTheme() {
      this.darkMode = !this.darkMode;
      localStorage.setItem('sharebook_theme', this.darkMode ? 'dark' : 'light');
      this._applyTheme();
    },
    _applyTheme() {
      document.documentElement.classList.toggle('dark', this.darkMode);
      document.documentElement.style.colorScheme = this.darkMode ? 'dark' : 'light';
    },

    // ── Crypto helpers ─────────────────────────────────────
    _bufToB64(buf) {
      const bytes = new Uint8Array(buf);
      let s = '';
      for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
      return btoa(s);
    },
    _b64ToBuf(b64) {
      const s = atob(b64);
      const bytes = new Uint8Array(s.length);
      for (let i = 0; i < s.length; i++) bytes[i] = s.charCodeAt(i);
      return bytes.buffer;
    },
    async _deriveKey(password, salt) {
      const enc = new TextEncoder();
      const keyMaterial = await crypto.subtle.importKey(
        'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
      );
      return crypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt,
          iterations: CRYPTO.PBKDF2_ITERATIONS,
          hash: 'SHA-256',
        },
        keyMaterial,
        { name: 'AES-GCM', length: CRYPTO.KEY_BITS },
        false,
        ['encrypt', 'decrypt']
      );
    },
    async _encrypt(data, key) {
      const iv = crypto.getRandomValues(new Uint8Array(CRYPTO.IV_BYTES));
      const enc = new TextEncoder();
      const cipher = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        enc.encode(JSON.stringify(data))
      );
      return {
        iv: this._bufToB64(iv),
        data: this._bufToB64(cipher),
      };
    },
    async _decrypt(payload, key) {
      const iv = this._b64ToBuf(payload.iv);
      const data = this._b64ToBuf(payload.data);
      const plain = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        key,
        data
      );
      return JSON.parse(new TextDecoder().decode(plain));
    },

    // ── Meta / vault persistence ───────────────────────────
    _readMeta() {
      try {
        return JSON.parse(localStorage.getItem('promptbook_meta') || 'null');
      } catch { return null; }
    },
    _writeMeta(meta) {
      localStorage.setItem('promptbook_meta', JSON.stringify(meta));
    },
    async _saveVault() {
      if (!this._cryptoKey) return;
      // 剝離 UI-only 欄位，避免污染加密資料模型
      const clean = this.prompts.map(({ _promptOpen, ...rest }) => rest);
      const payload = await this._encrypt({
        version: 1,
        items: clean,
        categories: this.categories,
      }, this._cryptoKey);
      localStorage.setItem('promptbook_vault', JSON.stringify(payload));
    },
    async _loadVault() {
      const raw = localStorage.getItem('promptbook_vault');
      if (!raw || !this._cryptoKey) return [];
      const payload = JSON.parse(raw);
      const data = await this._decrypt(payload, this._cryptoKey);
      if (Array.isArray(data)) {
        this.categories = this._categoriesForItems(DEFAULT_CATEGORIES, data);
        return data;
      }
      if (!data || !Array.isArray(data.items)) throw new Error('Vault format invalid');
      this.categories = this._categoriesForItems(data.categories, data.items);
      return data.items;
    },

    _categoriesForItems(categories, items = []) {
      const result = Array.isArray(categories)
        ? categories.filter(category => typeof category === 'string').map(category => category.trim()).filter(Boolean)
        : [...DEFAULT_CATEGORIES];
      for (const item of items) {
        const category = typeof item?.category === 'string' ? item.category.trim() : '';
        if (category && !result.includes(category)) result.push(category);
      }
      return result.length ? [...new Set(result)] : [...DEFAULT_CATEGORIES];
    },
    openCategoryDialog() {
      this.categoryDrafts = this.categories.map(name => ({ original: name, name, removed: false }));
      this.categoryDialogOpen = true;
    },
    addCategoryDraft() {
      this.categoryDrafts.push({ original: null, name: '', removed: false });
    },
    removeCategoryDraft(index) {
      this.categoryDrafts[index].removed = true;
    },
    restoreCategoryDraft(index) {
      this.categoryDrafts[index].removed = false;
    },
    async saveCategorySettings() {
      const rows = this.categoryDrafts.filter(row => !row.removed);
      const names = rows.map(row => row.name.trim());
      if (names.some(name => !name)) {
        this.showToast('分類名稱不可留白', 'error');
        return;
      }
      if (new Set(names.map(name => name.toLowerCase())).size !== names.length) {
        this.showToast('分類名稱不可重複', 'error');
        return;
      }
      if (!names.length) {
        this.showToast('至少保留一個分類', 'error');
        return;
      }

      const previousCategories = this.categories;
      const previousPrompts = this.prompts;
      const fallback = names.includes('其他') ? '其他' : names[0];
      const renamed = new Map(rows.filter(row => row.original && row.original !== row.name.trim())
        .map(row => [row.original, row.name.trim()]));
      const removed = new Set(this.categoryDrafts.filter(row => row.removed && row.original).map(row => row.original));
      this.categories = names;
      this.prompts = this.prompts.map(item => ({
        ...item,
        category: renamed.get(item.category) || (removed.has(item.category) ? fallback : item.category),
      }));

      try {
        await this._saveVault();
        this.categoryDialogOpen = false;
        this.showToast('分類已更新', 'success');
      } catch (e) {
        console.error(e);
        this.categories = previousCategories;
        this.prompts = previousPrompts;
        this.showToast('分類儲存失敗：本機儲存空間不足', 'error');
      }
    },

    openSyncDialog() {
      this.authError = '';
      this.syncDialogOpen = true;
      if (this.isLoggedIn) {
        this._refreshRemoteMeta().catch(() => {});
      }
    },

    // ── Supabase Auth ──────────────────────────────────────
    async signInWithEmail() {
      this.authError = '';
      const email = (this.authEmail || '').trim();
      const password = this.authPassword || '';
      if (!email || !password) {
        this.authError = '請輸入 Email 與密碼';
        return;
      }
      if (!this._supabase) {
        this.authError = 'Supabase 尚未載入，請重新整理頁面';
        return;
      }
      this.authLoading = true;
      try {
        const { data, error } = await this._supabase.auth.signInWithPassword({ email, password });
        if (error) throw error;
        this.authUser = data.user;
        this.authPassword = '';
        this.showToast('已登入', 'success');
        await this._refreshRemoteMeta();
      } catch (err) {
        console.error(err);
        this.authError = err?.message || '登入失敗，請檢查 Email / 密碼';
      } finally {
        this.authLoading = false;
      }
    },

    async signUpWithEmail() {
      this.authError = '';
      const email = (this.authEmail || '').trim();
      const password = this.authPassword || '';
      if (!email || !password) {
        this.authError = '請輸入 Email 與密碼';
        return;
      }
      if (password.length < 6) {
        this.authError = '密碼至少 6 個字元';
        return;
      }
      if (!this._supabase) {
        this.authError = 'Supabase 尚未載入，請重新整理頁面';
        return;
      }
      this.authLoading = true;
      try {
        const { data, error } = await this._supabase.auth.signUp({ email, password });
        if (error) throw error;
        this.authUser = data.user;
        this.authPassword = '';
        if (data.session) {
          this.showToast('註冊成功並已登入', 'success');
        } else {
          this.showToast('註冊成功，請檢查 Email 確認信（若已啟用）', 'success');
        }
        await this._refreshRemoteMeta();
      } catch (err) {
        console.error(err);
        this.authError = err?.message || '註冊失敗';
      } finally {
        this.authLoading = false;
      }
    },

    async signOut() {
      if (!this._supabase) return;
      try {
        await this._supabase.auth.signOut();
      } catch (e) {
        console.error(e);
      }
      this.authUser = null;
      this.lastSyncedAt = null;
      this.remoteUpdatedAt = null;
      this.showToast('已登出', 'success');
    },

    // ── Cloud Sync (E2EE: only encrypted vault) ────────────
    _buildCloudPayload() {
      const meta = this._readMeta();
      const vaultRaw = localStorage.getItem('promptbook_vault');
      if (!meta?.salt || !vaultRaw) return null;
      let vault;
      try {
        vault = JSON.parse(vaultRaw);
      } catch {
        return null;
      }
      return {
        version: 1,
        app: APP_NAME,
        meta: {
          version: meta.version || 1,
          salt: meta.salt,
          iterations: meta.iterations || CRYPTO.PBKDF2_ITERATIONS,
          createdAt: meta.createdAt || Date.now(),
        },
        vault,
        // optional client hint
        clientUpdatedAt: Date.now(),
      };
    },

    async _refreshRemoteMeta() {
      if (!this._supabase || !this.isLoggedIn) return;
      try {
        const { data, error } = await this._supabase
          .from('app_data')
          .select('updated_at')
          .eq('owner', this.authUser.id)
          .eq('app', APP_NAME)
          .maybeSingle();
        if (error) throw error;
        this.remoteUpdatedAt = data?.updated_at || null;
      } catch (e) {
        console.warn('[提示本本] 讀取遠端時間失敗', e);
        this.remoteUpdatedAt = null;
      }
    },

    async pushToCloud() {
      if (!this.isUnlocked) {
        this.showToast('請先解鎖本機資料', 'error');
        return;
      }
      if (!this.isLoggedIn || !this._supabase) {
        this.showToast('請先登入雲端帳號', 'error');
        return;
      }
      if (!this.isOnline) {
        this.showToast('目前離線，無法同步', 'error');
        return;
      }
      // Ensure vault is fresh
      try {
        await this._saveVault();
      } catch (e) {
        this.showToast('本機儲存失敗，無法上傳', 'error');
        return;
      }
      const payload = this._buildCloudPayload();
      if (!payload) {
        this.showToast('沒有可上傳的加密資料', 'error');
        return;
      }
      this.isSyncing = true;
      try {
        const { error } = await this._supabase
          .from('app_data')
          .upsert(
            {
              owner: this.authUser.id,
              app: APP_NAME,
              data: payload,
              updated_at: new Date().toISOString(),
            },
            { onConflict: 'owner,app' }
          );
        if (error) throw error;
        this.lastSyncedAt = Date.now();
        await this._refreshRemoteMeta();
        this.showToast('已上傳加密資料到雲端', 'success');
      } catch (err) {
        console.error(err);
        const msg = err?.message || '';
        if (msg.includes('duplicate') || msg.includes('unique')) {
          this.showToast('上傳失敗：資料衝突，請改用「從雲端拉取」後再試', 'error');
        } else if (msg.includes('policy') || msg.includes('permission') || msg.includes('RLS')) {
          this.showToast('上傳失敗：權限不足，請確認 RLS 政策允許本人寫入', 'error');
        } else {
          this.showToast('上傳失敗：' + (msg || '未知錯誤'), 'error');
        }
      } finally {
        this.isSyncing = false;
      }
    },

    async pullFromCloud() {
      if (!this.isLoggedIn || !this._supabase) {
        this.showToast('請先登入雲端帳號', 'error');
        return;
      }
      if (!this.isOnline) {
        this.showToast('目前離線，無法同步', 'error');
        return;
      }
      this.isSyncing = true;
      try {
        const { data: row, error } = await this._supabase
          .from('app_data')
          .select('data, updated_at')
          .eq('owner', this.authUser.id)
          .eq('app', APP_NAME)
          .maybeSingle();
        if (error) throw error;
        if (!row?.data) {
          this.showToast('雲端尚無此帳號的加密資料', 'error');
          return;
        }
        const remote = row.data;
        if (!remote?.meta?.salt || !remote?.vault?.iv || !remote?.vault?.data) {
          this.showToast('雲端資料格式不正確', 'error');
          return;
        }

        // Write encrypted vault + meta to localStorage (still encrypted)
        this._writeMeta({
          version: remote.meta.version || 1,
          salt: remote.meta.salt,
          iterations: remote.meta.iterations || CRYPTO.PBKDF2_ITERATIONS,
          createdAt: remote.meta.createdAt || Date.now(),
        });
        localStorage.setItem('promptbook_vault', JSON.stringify(remote.vault));

        this.hasMasterPassword = true;
        this.isFirstSetup = false;
        this.remoteUpdatedAt = row.updated_at || null;
        this.lastSyncedAt = Date.now();

        // If currently unlocked, try to re-load with existing key (same master password)
        if (this.isUnlocked && this._cryptoKey) {
          try {
            this.prompts = await this._loadVault();
            this.prompts = this.prompts.map((p, i) => ({
              ...p,
              id: p.id ?? (Date.now() + i),
              _promptOpen: false,
            }));
            this.showToast('已從雲端拉取並解密更新', 'success');
          } catch (decErr) {
            // Different master password → force re-lock
            this.lock();
            this.showToast('已拉取雲端資料，請用正確主密碼重新解鎖', 'success');
          }
        } else {
          // Locked state: just replace local encrypted data
          this.isLocked = true;
          this.isUnlocked = false;
          this.prompts = [];
          this._cryptoKey = null;
          this.showToast('已從雲端拉取加密資料，請解鎖', 'success');
        }
      } catch (err) {
        console.error(err);
        this.showToast('拉取失敗：' + (err?.message || '未知錯誤'), 'error');
      } finally {
        this.isSyncing = false;
      }
    },

    // ── Export helpers ─────────────────────────────────────
    _exportData() {
      return {
        app: 'promptbook',
        version: 1,
        categories: [...this.categories],
        items: this.prompts.map(({ _promptOpen, ...item }) => item),
      };
    },
    // ── Unlock / Setup ─────────────────────────────────────
    async setupMasterPassword() {
      this.unlockError = '';
      const pw = this.masterPasswordInput.trim();
      const confirm = this.confirmPasswordInput.trim();
      if (pw.length < 8) {
        this.unlockError = '主密碼至少需要 8 個字元';
        return;
      }
      if (pw !== confirm) {
        this.unlockError = '兩次輸入的密碼不一致';
        return;
      }
      this.isProcessing = true;
      try {
        const salt = crypto.getRandomValues(new Uint8Array(CRYPTO.SALT_BYTES));
        this._salt = salt;
        this._cryptoKey = await this._deriveKey(pw, salt);
        this._writeMeta({
          version: 1,
          salt: this._bufToB64(salt),
          iterations: CRYPTO.PBKDF2_ITERATIONS,
          createdAt: Date.now(),
        });
        // Create the encrypted vault before unlocking the empty notebook.
        await this._saveVault();
        this.hasMasterPassword = true;
        this.isFirstSetup = false;
        this.isLocked = false;
        this.isUnlocked = true;
        this.masterPasswordInput = '';
        this.confirmPasswordInput = '';
        this.showToast('主密碼已設定，資料已加密保護', 'success');
      } catch (err) {
        console.error(err);
        this.unlockError = '設定失敗，請再試一次';
      } finally {
        this.isProcessing = false;
      }
    },

    async unlock() {
      this.unlockError = '';
      const pw = this.masterPasswordInput;
      if (!pw) {
        this.unlockError = '請輸入主密碼';
        return;
      }
      this.isProcessing = true;
      try {
        const meta = this._readMeta();
        if (!meta?.salt) throw new Error('No meta');
        const salt = this._b64ToBuf(meta.salt);
        this._salt = salt;
        this._cryptoKey = await this._deriveKey(pw, salt);
        this.prompts = await this._loadVault();
        // Ensure each item has a stable id
        this.prompts = this.prompts.map((p, i) => ({
          ...p,
          id: p.id ?? (Date.now() + i),
          _promptOpen: false,
        }));
        this.isLocked = false;
        this.isUnlocked = true;
        this.masterPasswordInput = '';
        this.showToast('已解鎖', 'success');
      } catch (err) {
        console.error(err);
        this._cryptoKey = null;
        this.unlockError = '主密碼錯誤或資料損毀';
      } finally {
        this.isProcessing = false;
      }
    },

    lock() {
      this._cryptoKey = null;
      this.prompts = [];
      this.isUnlocked = false;
      this.isLocked = true;
      this.searchQuery = '';
      this.closeModal();
      this.cancelImport();
      this.masterPasswordInput = '';
      this.unlockError = '';
      // Signal other tabs
      try {
        localStorage.setItem('promptbook_lock_signal', String(Date.now()));
      } catch {}
    },

    // ── CRUD ───────────────────────────────────────────────
    openModal(item = null) {
      if (item) {
        this.editingId = item.id;
        this.formData = {
          title: item.title || '',
          category: item.category || '',
          tags: item.tags || '',
          prompt: item.prompt || '',
          notes: item.notes || '',
        };
      } else {
        this.editingId = null;
        this.formData = { title: '', category: '', tags: '', prompt: '', notes: '' };
      }
      this.isModalOpen = true;
    },
    closeModal() {
      this.isModalOpen = false;
      this.editingId = null;
    },
    async saveItem() {
      const d = this.formData;
      if (!d.title?.trim() || !d.prompt?.trim()) {
        this.showToast('請填寫必填欄位', 'error');
        return;
      }
      const wasEditing = this.editingId != null;
      try {
        if (wasEditing) {
          const idx = this.prompts.findIndex(p => p.id === this.editingId);
          if (idx !== -1) {
            this.prompts[idx] = {
              ...this.prompts[idx],
              title: d.title.trim(),
              category: (d.category || '').trim(),
              tags: (d.tags || '').trim(),
              prompt: d.prompt.trim(),
              notes: (d.notes || '').trim(),
            };
          }
        } else {
          this.prompts.unshift({
            id: Date.now() + Math.random(),
            title: d.title.trim(),
            category: (d.category || '').trim(),
            tags: (d.tags || '').trim(),
            prompt: d.prompt.trim(),
            notes: (d.notes || '').trim(),
            createdAt: Date.now(),
            favorite: false,
            _promptOpen: false,
          });
        }
        await this._saveVault();
        this.closeModal();
        this.showToast(wasEditing ? '已更新 Prompt' : '已收藏 Prompt', 'success');
      } catch (e) {
        console.error(e);
        this.showToast('儲存失敗：本機儲存空間不足', 'error');
      }
    },
    async deleteItem(id) {
      if (!confirm('確定要刪除此項目？')) return;
      const snapshot = this.prompts;
      try {
        this.prompts = this.prompts.filter(p => p.id !== id);
        await this._saveVault();
        this.showToast('已刪除', 'success');
      } catch (e) {
        console.error(e);
        this.prompts = snapshot;
        this.showToast('刪除失敗：本機儲存空間不足', 'error');
      }
    },
    editItem(item) {
      this.openModal(item);
    },

    async toggleFavorite(item) {
      const previous = item.favorite;
      item.favorite = !previous;
      try {
        await this._saveVault();
        this.showToast(item.favorite ? '已加入最愛' : '已取消最愛', 'success');
      } catch (e) {
        console.error(e);
        item.favorite = previous;
        this.showToast('更新失敗：本機儲存空間不足', 'error');
      }
    },

    // ── Clipboard ──────────────────────────────────────────
    async copyToClipboard(text, msg = '已複製') {
      if (!text) return;
      try {
        await navigator.clipboard.writeText(text);
        this.showToast(msg, 'success');
      } catch {
        // Fallback
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.style.cssText = 'position:fixed;left:-9999px';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        this.showToast(msg, 'success');
      }
    },

    // ── Export / Import ────────────────────────────────────
    exportToJson() {
      if (!this.isUnlocked) return;
      const blob = new Blob([JSON.stringify(this._exportData(), null, 2)], { type: 'application/json' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `提示本本-備份-${new Date().toISOString().slice(0, 10)}.json`;
      a.click();
      // Safari / iOS：延遲 revoke，避免下載尚未開始就失效
      setTimeout(() => URL.revokeObjectURL(a.href), 1000);
      this.showToast('JSON 已匯出', 'success');
    },
    async importFromJson(event) {
      const file = event.target.files?.[0];
      if (!file) return;
      try {
        const text = await file.text();
        const data = JSON.parse(text);
        const dataItems = Array.isArray(data) ? data : data?.app === 'promptbook' && Array.isArray(data.items) ? data.items : null;
        if (!dataItems) throw new Error('格式錯誤');
        const mapped = dataItems.map((p, i) => p && typeof p === 'object' ? ({
          id: p.id ?? (Date.now() + i + Math.random()),
          title: String(p.title || p.name || ''),
          category: String(p.category || ''),
          prompt: String(p.prompt || p.content || p.text || ''),
          notes: String(p.notes || ''),
          tags: String(p.tags || ''),
          favorite: Boolean(p.favorite),
          createdAt: p.createdAt || Date.now(),
          _promptOpen: false,
        }) : null).filter(p => p?.title && p.prompt);
        if (mapped.length === 0) {
          this.showToast('檔案內沒有有效的 Prompt', 'error');
          event.target.value = '';
          return;
        }
        // 開啟選擇：合併 / 取代
        this.importPreview = mapped;
        this.importPreviewCategories = this._categoriesForItems(
          Array.isArray(data) ? DEFAULT_CATEGORIES : data.categories,
          mapped
        );
        this.importDialogOpen = true;
      } catch (e) {
        this.showToast('匯入失敗：檔案格式不正確', 'error');
      }
      event.target.value = '';
    },
    cancelImport() {
      this.importDialogOpen = false;
      this.importPreview = [];
      this.importPreviewCategories = [];
    },
    async confirmImport(mode) {
      // mode: 'merge' | 'replace'
      const mapped = this.importPreview;
      if (!mapped?.length) {
        this.cancelImport();
        return;
      }
      const previousPrompts = this.prompts;
      const previousCategories = this.categories;
      try {
        if (mode === 'replace') {
          this.prompts = mapped;
          this.categories = [...this.importPreviewCategories];
          await this._saveVault();
          this.showToast(`已取代，共 ${mapped.length} 筆`, 'success');
        } else {
          // 合併：新資料放前面，保留既有
          this.prompts = [...mapped, ...this.prompts];
          this.categories = this._categoriesForItems([...this.categories, ...this.importPreviewCategories], this.prompts);
          await this._saveVault();
          this.showToast(`已合併匯入 ${mapped.length} 筆`, 'success');
        }
      } catch (e) {
        console.error(e);
        this.prompts = previousPrompts;
        this.categories = previousCategories;
        this.showToast('匯入失敗：本機儲存空間不足', 'error');
      }
      this.cancelImport();
    },
    // ── Utils ──────────────────────────────────────────────
    showToast(message, type = 'info') {
      const id = Date.now() + Math.random();
      this.toasts.push({ id, message, type });
      setTimeout(() => {
        this.toasts = this.toasts.filter(t => t.id !== id);
      }, 2800);
    },

    formatTime(ts) {
      if (!ts) return '—';
      try {
        const d = typeof ts === 'number' ? new Date(ts) : new Date(ts);
        if (Number.isNaN(d.getTime())) return '—';
        return d.toLocaleString('zh-HK', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' });
      } catch {
        return '—';
      }
    },
  };
}
