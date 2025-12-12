async function api(url, opt = {}) {
  opt.headers = opt.headers || {};
  if (opt.body && typeof opt.body !== 'string') {
    opt.headers['Content-Type'] = 'application/json';
    opt.body = JSON.stringify(opt.body);
  }
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes((opt.method || 'GET').toUpperCase())) {
    try {
      if (!window.__CSRF) {
        window.__CSRF = (await fetch('/csrf').then(r => r.json())).token;
      }
      opt.headers['x-csrf-token'] = window.__CSRF || '';
    } catch {}
  }
  const r = await fetch(url, opt);
  if (!r.ok) {
    let msg;
    try { msg = await r.json(); } catch { msg = { error: await r.text() }; }
    const err = new Error(msg && msg.error ? msg.error : (r.status + ''));
    err.status = r.status;
    throw err;
  }
  const ct = r.headers.get('content-type') || '';
  if (ct.includes('application/json')) return r.json();
  return r.text();
}

// Formato de fecha para la tabla (DD-MM-YYYY [HH:MM])
function formatDateForTable(value, withTime = false) {
  if (!value) return '';
  const d = new Date(value);
  if (!isNaN(d.getTime())) {
    const dd = String(d.getDate()).padStart(2, '0');
    const mm = String(d.getMonth() + 1).padStart(2, '0');
    const yy = d.getFullYear();
    if (withTime) {
      const hh = String(d.getHours()).padStart(2, '0');
      const mi = String(d.getMinutes()).padStart(2, '0');
      if (hh !== '00' || mi !== '00') {
        return `${dd}-${mm}-${yy} ${hh}:${mi}`;
      }
    }
    return `${dd}-${mm}-${yy}`;
  }
  // fallback: si no se puede parsear, devolvemos lo que venga
  return String(value);
}

// Estado global para saber si estamos editando algo
window.__editing = { scope: null, id: null };

// Filtros por rango de fechas (YYYY-MM-DD) por módulo
window.__filters = window.__filters || {
  recepciones: { from: '', to: '', q: '', min: '', max: '' },
  produccion: { from: '', to: '', q: '', min: '', max: '' },
  defectuosos: { from: '', to: '', q: '', min: '', max: '' },
  envios: { from: '', to: '', q: '', min: '', max: '' }
};

function buildFilterQuery(scope) {
  const f = (window.__filters && window.__filters[scope]) || { from: '', to: '', q: '', min: '', max: '' };
  const qs = new URLSearchParams();
  if (f.from) qs.set('from', f.from);
  if (f.to) qs.set('to', f.to);
  if (f.q) qs.set('q', f.q);
  if (f.min !== undefined && f.min !== null && String(f.min).trim() !== '') qs.set('min', String(f.min).trim());
  if (f.max !== undefined && f.max !== null && String(f.max).trim() !== '') qs.set('max', String(f.max).trim());
  const s = qs.toString();
  return s ? `?${s}` : '';
}

function setEditing(scope, id) {
  window.__editing = { scope, id };
}

function clearEditing() {
  window.__editing = { scope: null, id: null };
}

// Rellena el formulario correspondiente con los datos del registro
function fillForm(scope, record) {
  const form = document.querySelector(`form[data-form="${scope}"]`);
  if (!form) return;

  if (scope === 'recepciones') {
    if (form.fecha) form.fecha.value = record.fecha || '';
    if (form.tipo) form.tipo.value = record.tipo || '';
    if (form.cantidad) form.cantidad.value = record.cantidad || '';
    if (form.unidad) form.unidad.value = record.unidad || '';
  }

  if (scope === 'produccion') {
    if (form.fecha_ini) form.fecha_ini.value = record.fecha_ini || '';
    if (form.tipo) form.tipo.value = record.tipo || '';
    if (form.cantidad) form.cantidad.value = record.cantidad || '';
    if (form.unidad) form.unidad.value = record.unidad || '';
  }

  if (scope === 'defectuosos') {
    if (form.fecha) form.fecha.value = record.fecha || '';
    if (form.tipo) form.tipo.value = record.tipo || '';
    if (form.cantidad) form.cantidad.value = record.cantidad || '';
    if (form.unidad) form.unidad.value = record.unidad || '';
    if (form.razon) form.razon.value = record.razon || '';
  }

  if (scope === 'envios') {
    if (form.fecha) form.fecha.value = record.fecha || '';
    if (form.cliente) form.cliente.value = record.cliente || '';
    if (form.tipo) form.tipo.value = record.tipo || '';
    if (form.descripcion) form.descripcion.value = record.descripcion || '';
    if (form.cantidad) form.cantidad.value = record.cantidad || '';
    if (form.unidad) form.unidad.value = record.unidad || '';
  }
}

function hookForm(scope) {
  const form = document.querySelector(`form[data-form="${scope}"]`);
  if (!form) return;

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (window.__ROLE === 'operario') {
      alert('Solo visualización para Operario.');
      return;
    }

    const formData = new FormData(form);
    const payload = Object.fromEntries(formData.entries());

    const editing = window.__editing && window.__editing.scope === scope && window.__editing.id;

    try {
      if (editing) {
        await api(`/api/${scope}/${window.__editing.id}`, {
          method: 'PUT',
          body: payload
        });
      } else {
        await api(`/api/${scope}`, {
          method: 'POST',
          body: payload
        });
      }
      form.reset();
      clearEditing();
      await renderTable(scope);
    } catch (err) {
      console.error(err);
      alert('Error guardando datos');
    }
  });
}

async function renderTable(scope) {
  const tbl = document.querySelector(`table[data-table="${scope}"]`);
  if (!tbl) return;
  const data = await api(`/api/${scope}${buildFilterQuery(scope)}`);
  const tbody = tbl.querySelector('tbody');
  tbody.innerHTML = '';

  // Actualizar contador si existe
  const countEl = document.getElementById(`count-${scope}`);
  if (countEl) countEl.textContent = String((data.items || []).length);

  data.items.forEach(r => {
    const tr = document.createElement('tr');

    const addCell = (value, cls) => {
      const td = document.createElement('td');
      if (cls) td.className = cls;
      td.textContent = value == null ? '' : String(value);
      tr.appendChild(td);
    };

    if (scope === 'recepciones') {
      const fechaText = formatDateForTable(r.fecha, true);
      addCell(fechaText);
      addCell(r.tipo,'col-tipo');
      addCell(r.cantidad);
      addCell(r.unidad || '');
    }

    if (scope === 'produccion') {
      const fechaText = formatDateForTable(r.fecha_ini, true);
      addCell(fechaText);
      addCell(r.tipo || '','col-tipo');
      addCell(r.cantidad);
      addCell(r.unidad || '');
    }

    if (scope === 'defectuosos') {
      const fechaText = formatDateForTable(r.fecha, false);
      addCell(fechaText);
      addCell(r.tipo,'col-tipo');
      addCell(r.cantidad);
      addCell(r.unidad || '');
      addCell(r.razon || '');
    }

    if (scope === 'envios') {
      const fechaText = formatDateForTable(r.fecha, false);
      addCell(fechaText);
      addCell(r.cliente);
      addCell(r.tipo,'col-tipo');
      addCell(r.descripcion || '','col-detalle');
      addCell(r.cantidad);
      addCell(r.unidad || '');
    }

    // Columna de acciones (Editar / Eliminar)
    const tdActions = document.createElement('td');
    tdActions.className = 'actions-row';

    const btnEdit = document.createElement('button');
    btnEdit.type = 'button';
    btnEdit.className = 'btn-small btn-edit';
    btnEdit.dataset.id = r.id;
    btnEdit.textContent = 'Editar';

    const btnDel = document.createElement('button');
    btnDel.type = 'button';
    btnDel.className = 'btn-small btn-del';
    btnDel.dataset.id = r.id;
    btnDel.textContent = 'Eliminar';

    tdActions.appendChild(btnEdit);
    tdActions.appendChild(btnDel);
    tr.appendChild(tdActions);

    tbody.appendChild(tr);
  });

  // Botones eliminar
  tbody.querySelectorAll('.btn-del').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.preventDefault();
      if (window.__ROLE === 'operario') {
        alert('Solo visualización para Operario.');
        return;
      }
      if (!confirm('¿Eliminar registro?')) return;
      const id = btn.dataset.id;
      try {
        await api(`/api/${scope}/${id}`, { method: 'DELETE' });
        await renderTable(scope);
      } catch (err) {
        console.error(err);
        alert('Error eliminando registro');
      }
    });
  });

  // Botones editar
  tbody.querySelectorAll('.btn-edit').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      if (window.__ROLE === 'operario') {
        alert('Solo visualización para Operario.');
        return;
      }
      const id = btn.dataset.id;
      const rec = data.items.find(x => String(x.id) === String(id));
      if (!rec) return;
      setEditing(scope, id);
      fillForm(scope, rec);
      // ya no hacemos scroll hacia arriba para evitar el salto molesto
    });
  });
}

async function renderUsers() {
  const tbl = document.getElementById('usersTable');
  if (!tbl) return;
  const data = await api('/api/users');
  const tbody = tbl.querySelector('tbody');
  tbody.innerHTML = '';

  data.items.forEach(u => {
    const tr = document.createElement('tr');

    // Columna usuario
    const tdUser = document.createElement('td');
    tdUser.textContent = u.username;
    tr.appendChild(tdUser);

    // Columna rol (select)
    const tdRole = document.createElement('td');
    const sel = document.createElement('select');
    sel.className = 'input inline-edit roleSel';
    sel.dataset.id = u.id;

    ['operario', 'supervisor', 'administrador'].forEach(role => {
      const opt = document.createElement('option');
      opt.value = role;
      opt.textContent = role;
      if (u.role === role) opt.selected = true;
      sel.appendChild(opt);
    });

    tdRole.appendChild(sel);
    tr.appendChild(tdRole);

    // Columna acciones
    const tdActions = document.createElement('td');
    tdActions.className = 'actions-row';

    const btnReset = document.createElement('button');
    btnReset.type = 'button';
    btnReset.className = 'btn-small reset';
    btnReset.dataset.id = u.id;
    btnReset.textContent = 'Reset Pass';

    const btnDel = document.createElement('button');
    btnDel.type = 'button';
    btnDel.className = 'btn-small del';
    btnDel.dataset.id = u.id;
    btnDel.textContent = 'Eliminar';

    tdActions.appendChild(btnReset);
    tdActions.appendChild(btnDel);
    tr.appendChild(tdActions);

    tbody.appendChild(tr);
  });

  tbody.querySelectorAll('.roleSel').forEach(sel => {
    sel.addEventListener('change', async () => {
      await api('/api/users/' + sel.dataset.id, {
        method: 'PUT',
        body: { role: sel.value }
      });
      alert('Rol actualizado');
    });
  });

  tbody.querySelectorAll('.del').forEach(btn => {
    btn.addEventListener('click', async () => {
      if (!confirm('¿Eliminar usuario?')) return;
      await api('/api/users/' + btn.dataset.id, { method: 'DELETE' });
      renderUsers();
    });
  });

  tbody.querySelectorAll('.reset').forEach(btn => {
    btn.addEventListener('click', async () => {
      const p = prompt('Nueva contraseña', 'admin');
      if (!p) return;
      await api('/api/users/' + btn.dataset.id + '/password', {
        method: 'PATCH',
        body: { password: p }
      });
      alert('Contraseña cambiada');
    });
  });
}

async function initPanel() {
  const me = await api('/me');
  if (!me.user) {
    location.href = '/';
    return;
  }

  document.getElementById('whoami').textContent =
    me.user.username + ' (' + me.user.role + ')';

  window.__ROLE = me.user.role;

  if (me.user.role === 'operario') {
    document.body.classList.add('readonly');
  }

  // Mostrar secciones solo-supervisor para supervisor y administrador
  if (me.user.role === 'supervisor') {
    document.querySelectorAll('.only-supervisor').forEach(e => {
      e.style.display = 'block';
    });
  }

  ['recepciones', 'produccion', 'defectuosos', 'envios'].forEach(scope => {
    hookForm(scope);
    renderTable(scope).catch(err => {
      console.error(`Error cargando tabla ${scope}:`, err);
    });
  });

  // Hook filtros (from/to) y exportaciones (PDF/XLSX) por sección
  document.querySelectorAll('[data-filter-apply]').forEach(btn => {
    btn.addEventListener('click', async () => {
      const scope = btn.dataset.filterApply;
      const fromEl = document.querySelector(`[data-filter-from="${scope}"]`);
      const toEl = document.querySelector(`[data-filter-to="${scope}"]`);
      const qEl = document.querySelector(`[data-filter-q="${scope}"]`);
      const minEl = document.querySelector(`[data-filter-min="${scope}"]`);
      const maxEl = document.querySelector(`[data-filter-max="${scope}"]`);
      const from = fromEl ? String(fromEl.value || '') : '';
      const to = toEl ? String(toEl.value || '') : '';
      const q = qEl ? String(qEl.value || '').trim() : '';
      const min = minEl ? String(minEl.value || '').trim() : '';
      const max = maxEl ? String(maxEl.value || '').trim() : '';
      window.__filters[scope] = { from, to, q, min, max };
      try {
        await renderTable(scope);
      } catch (err) {
        console.error('Error aplicando filtro:', err);
        alert('No se pudo aplicar el filtro. Revisa consola.');
      }
    });
  });

  document.querySelectorAll('[data-filter-all]').forEach(btn => {
    btn.addEventListener('click', async () => {
      const scope = btn.dataset.filterAll;
      window.__filters[scope] = { from: '', to: '', q: '', min: '', max: '' };
      const fromEl = document.querySelector(`[data-filter-from="${scope}"]`);
      const toEl = document.querySelector(`[data-filter-to="${scope}"]`);
      if (fromEl) fromEl.value = '';
      if (toEl) toEl.value = '';
      const qEl = document.querySelector(`[data-filter-q="${scope}"]`);
      const minEl = document.querySelector(`[data-filter-min="${scope}"]`);
      const maxEl = document.querySelector(`[data-filter-max="${scope}"]`);
      if (qEl) qEl.value = '';
      if (minEl) minEl.value = '';
      if (maxEl) maxEl.value = '';
      try {
        await renderTable(scope);
      } catch (err) {
        console.error('Error mostrando todo:', err);
        alert('No se pudo refrescar la tabla. Revisa consola.');
      }
    });
  });

  
  // Limpiar filtros por sección
  document.querySelectorAll('[data-filter-clear]').forEach(btn => {
    btn.addEventListener('click', async () => {
      const scope = btn.dataset.filterClear;
      const fromEl = document.querySelector(`[data-filter-from="${scope}"]`);
      const toEl = document.querySelector(`[data-filter-to="${scope}"]`);
      const qEl = document.querySelector(`[data-filter-q="${scope}"]`);
      const minEl = document.querySelector(`[data-filter-min="${scope}"]`);
      const maxEl = document.querySelector(`[data-filter-max="${scope}"]`);
      if (fromEl) fromEl.value = '';
      if (toEl) toEl.value = '';
      if (qEl) qEl.value = '';
      if (minEl) minEl.value = '';
      if (maxEl) maxEl.value = '';
      window.__filters = window.__filters || {};
      window.__filters[scope] = { from: '', to: '', q: '', min: '', max: '' };
      try {
        await renderTable(scope);
      } catch (err) {
        console.error('Error limpiando filtros:', err);
        alert('No se pudo refrescar la tabla.');
      }
    });
  });

  // Botón "Ahora" (fecha/hora actual Perú) en todos los módulos
  document.querySelectorAll('.now-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const form = btn.closest('form');
      if (!form) return;
      const dt = form.querySelector('input[type="datetime-local"]');
      const d = form.querySelector('input[type="date"]');
      if (dt) dt.value = getLimaNowForDatetimeLocal();
      else if (d) d.value = getLimaTodayForDate();
    });
  });

  function getLimaTodayForDate() {
    // YYYY-MM-DD en America/Lima
    const parts = new Intl.DateTimeFormat('en-CA', {
      timeZone: 'America/Lima',
      year: 'numeric', month: '2-digit', day: '2-digit'
    }).formatToParts(new Date());
    const get = t => parts.find(p => p.type === t)?.value || '';
    return `${get('year')}-${get('month')}-${get('day')}`;
  }

  function getLimaNowForDatetimeLocal() {
    // YYYY-MM-DDTHH:MM en America/Lima
    const parts = new Intl.DateTimeFormat('en-CA', {
      timeZone: 'America/Lima',
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit',
      hour12: false
    }).formatToParts(new Date());
    const get = t => parts.find(p => p.type === t)?.value || '';
    return `${get('year')}-${get('month')}-${get('day')}T${get('hour')}:${get('minute')}`;
  }
document.querySelectorAll('[data-export]').forEach(btn => {
    btn.addEventListener('click', () => {
      const scope = btn.dataset.export;
      const fmt = btn.dataset.format || 'pdf';
      const qs = (btn.dataset.all === '1') ? '' : buildFilterQuery(scope);
      // Evita bloqueos de pop-ups: para descargas usamos navegación directa.
      // En caso de PDF el navegador lo abrirá o descargará según configuración.
      window.location.href = `/api/${scope}.${fmt}${qs}`;
    });
  });

  // Botones PDF
  document.querySelectorAll('[data-pdf]').forEach(btn => {
    btn.addEventListener('click', () => {
      const type = btn.dataset.pdf;
      // Si existe filtro activo en ese módulo, lo respetamos
      const qs = (window.__filters && window.__filters[type]) ? buildFilterQuery(type) : '';
      window.open(`/api/${type}.pdf${qs}`, '_blank');
    });
  });

  // Gestión de usuarios: SOLO supervisor o administrador
  const add = document.getElementById('addUser');
  const canManageUsers =
    me.user.role === 'supervisor' || me.user.role === 'administrador';

  if (add && canManageUsers) {
    add.addEventListener('click', async () => {
      const uname = document.getElementById('nu_user').value.trim();
      const role = document.getElementById('nu_role').value;
      const pass = document.getElementById('nu_pass').value;
      await api('/api/users', {
        method: 'POST',
        body: { username: uname, role, password: pass }
      });
      document.getElementById('nu_user').value = '';
      await renderUsers();
    });

    // Carga inicial de usuarios protegida por rol
    try {
      await renderUsers();
    } catch (err) {
      console.error('Error cargando usuarios:', err);
    }
  }

  // Botón Salir: debe funcionar PARA TODOS LOS ROLES
  const lo = document.getElementById('logoutBtn');
  if (lo) {
    lo.addEventListener('click', async () => {
      try {
        await api('/api/auth/logout', { method: 'POST' });
      } catch (err) {
        console.error('Error en logout:', err);
      }
      location.href = '/';
    });
  }
}

document.addEventListener('DOMContentLoaded', () => {

// ===== Tema (claro/oscuro) =====
const THEME_KEY = 'brumapp_theme';
const applyTheme = (t) => {
  document.body.classList.toggle('theme-light', t === 'light');
};
try{
  const saved = localStorage.getItem(THEME_KEY) || 'dark';
  applyTheme(saved);
}catch(e){}
const themeBtn = document.getElementById('themeToggle');
if (themeBtn){
  themeBtn.addEventListener('click', () => {
    const isLight = document.body.classList.contains('theme-light');
    const next = isLight ? 'dark' : 'light';
    applyTheme(next);
    try{ localStorage.setItem(THEME_KEY, next); }catch(e){}
  });
}


  // En algunos despliegues (reverse proxy / subpath) el pathname puede variar.
  // Usamos un chequeo más flexible para asegurar que el panel inicialice.
  if (String(location.pathname || '').endsWith('panel.html')) initPanel();
});
