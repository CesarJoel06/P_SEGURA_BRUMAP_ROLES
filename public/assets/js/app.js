
async function api(url, opt = {}) {
  opt.headers = opt.headers || {};

  // OWASP A03 (Injection) / A05 (Security Misconfiguration):
  // Se fuerza el uso de JSON como formato de intercambio de datos, evitando concatenaciones de cadenas
  // que podrían favorecer inyecciones y manteniendo una configuración consistente de Content-Type.
  if (opt.body && typeof opt.body !== 'string') {
    opt.headers['Content-Type'] = 'application/json';
    opt.body = JSON.stringify(opt.body);
  }

  // OWASP A01 (Broken Access Control) / A05:
  // Para métodos que modifican estado, se envía un token CSRF en cabecera dedicada.
  // Esto ayuda a mitigar ataques de falsificación de petición en sitios cruzados (CSRF),
  // siempre que el backend valide correctamente este token.
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes((opt.method || 'GET').toUpperCase())) {
    try {
      if (!window.__CSRF) {
        window.__CSRF = (await fetch('/csrf').then(r => r.json())).token;
      }
      opt.headers['x-csrf-token'] = window.__CSRF || '';
    } catch {}
  }

  const r = await fetch(url, opt);

  // OWASP A05 (Security Misconfiguration):
  // Manejo de errores evitando exponer directamente respuestas sin procesar;
  // el front muestra mensajes genéricos y deja detalles para el servidor o consola de desarrollo.
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

// OWASP A03 (Injection):
// Se formatea la fecha sin concatenar valores en HTML y devolviendo texto simple.
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
  return String(value);
}

// OWASP A01 (Broken Access Control):
// Estado global para gestionar qué registro se está editando, controlado luego por rol.
window.__editing = { scope: null, id: null };

function setEditing(scope, id) {
  window.__editing = { scope, id };
}

function clearEditing() {
  window.__editing = { scope: null, id: null };
}

// OWASP A03 (Injection):
// Relleno de formularios directamente en los campos, sin construir HTML ni usar innerHTML.
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

    // OWASP A01 (Broken Access Control):
    // El rol "operario" solo tiene permisos de lectura.
    // Se evita que ejecute acciones de escritura (POST/PUT) desde el cliente.
    // Importante: el control definitivo debe existir en el servidor.
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
      // OWASP A05 (Security Misconfiguration):
      // Mensaje genérico hacia el usuario, evitando revelar detalles internos de errores.
      alert('Error guardando datos');
    }
  });
}

async function renderTable(scope) {
  const tbl = document.querySelector(`table[data-table="${scope}"]`);
  if (!tbl) return;
  const data = await api(`/api/${scope}`);
  const tbody = tbl.querySelector('tbody');
  tbody.innerHTML = '';

  data.items.forEach(r => {
    const tr = document.createElement('tr');

    // OWASP A03 (Injection):
    // Se usa textContent para insertar datos en la tabla, evitando interpretrar HTML dinámico
    // que pueda contener scripts (mitigación de XSS reflejado/almacenado en el front).
    const addCell = (value) => {
      const td = document.createElement('td');
      td.textContent = value == null ? '' : String(value);
      tr.appendChild(td);
    };

    if (scope === 'recepciones') {
      const fechaText = formatDateForTable(r.fecha, true);
      addCell(fechaText);
      addCell(r.tipo);
      addCell(r.cantidad);
      addCell(r.unidad || '');
    }

    if (scope === 'produccion') {
      const fechaText = formatDateForTable(r.fecha_ini, true);
      addCell(fechaText);
      addCell(r.tipo || '');
      addCell(r.cantidad);
      addCell(r.unidad || '');
    }

    if (scope === 'defectuosos') {
      const fechaText = formatDateForTable(r.fecha, false);
      addCell(fechaText);
      addCell(r.tipo);
      addCell(r.cantidad);
      addCell(r.unidad || '');
      addCell(r.razon || '');
    }

    if (scope === 'envios') {
      const fechaText = formatDateForTable(r.fecha, false);
      addCell(fechaText);
      addCell(r.cliente);
      addCell(r.tipo);
      addCell(r.descripcion || '');
      addCell(r.cantidad);
      addCell(r.unidad || '');
    }

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

  tbody.querySelectorAll('.btn-del').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.preventDefault();

      // OWASP A01 (Broken Access Control):
      // De nuevo, control de permisos de borrado a nivel de UI según rol.
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

  tbody.querySelectorAll('.btn-edit').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();

      // OWASP A01 (Broken Access Control):
      // El rol "operario" tampoco puede iniciar flujos de edición de datos.
      if (window.__ROLE === 'operario') {
        alert('Solo visualización para Operario.');
        return;
      }

      const id = btn.dataset.id;
      const rec = data.items.find(x => String(x.id) === String(id));
      if (!rec) return;
      setEditing(scope, id);
      fillForm(scope, rec);
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

    const tdUser = document.createElement('td');
    tdUser.textContent = u.username;
    tr.appendChild(tdUser);

    // OWASP A01 (Broken Access Control):
    // Edición de roles solo disponible cuando la UI de administración de usuarios
    // está visible (controlada por el rol supervisor en initPanel).
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

  // OWASP A07 (Identification & Authentication Failures) / A01:
  // Reseteo de contraseña solo accesible desde la UI de administración (visible solo a supervisores).
  // El back debe seguir validando que solo perfiles autorizados pueden cambiar contraseñas.
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
  // OWASP A07 (Identification & Authentication Failures):
  // Antes de inicializar el panel, se consulta /me para comprobar que hay un usuario autenticado.
  // Si no existe, se redirige a la pantalla pública de login.
  const me = await api('/me');
  if (!me.user) {
    location.href = '/';
    return;
  }

  document.getElementById('whoami').textContent =
    me.user.username + ' (' + me.user.role + ')';

  window.__ROLE = me.user.role;
  const isSupervisor = me.user.role === 'supervisor';

  // OWASP A01:
  // Se marca visualmente (clase readonly) a usuarios sin permisos de edición.
  if (me.user.role === 'operario') {
    document.body.classList.add('readonly');
  }

  // OWASP A01:
  // Lógica de mostrar/ocultar secciones de solo supervisor directamente en la UI.
  if (isSupervisor) {
    document.querySelectorAll('.only-supervisor').forEach(e => {
      e.style.display = 'block';
    });
  } else {
    document.querySelectorAll('.only-supervisor').forEach(e => {
      e.style.display = 'none';
    });
  }

  ['recepciones', 'produccion', 'defectuosos', 'envios'].forEach(scope => {
    hookForm(scope);
    renderTable(scope);
  });

  // OWASP A03:
  // Exportación en PDF se limita a llamadas HTTP; se usa window.open sin inyectar HTML dinámico.
  document.querySelectorAll('[data-pdf]').forEach(btn => {
    btn.addEventListener('click', () => {
      const type = btn.dataset.pdf;
      window.open(`/api/${type}.pdf`, '_blank');
    });
  });

  // Gestión de usuarios: SOLO SUPERVISOR
  const add = document.getElementById('addUser');

  if (add && isSupervisor) {
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

    try {
      await renderUsers();
    } catch (err) {
      console.error('Error cargando usuarios:', err);
    }
  }

  // OWASP A01:
  // Para roles que NO son supervisor, se oculta por completo el panel de usuarios en la UI.
  if (!isSupervisor) {
    const usersTable = document.getElementById('usersTable');
    const addBtn = document.getElementById('addUser');
    let usersPanel = null;

    if (usersTable) {
      usersPanel =
        usersTable.closest('section') ||
        usersTable.closest('.card') ||
        usersTable.closest('.panel') ||
        usersTable.closest('div');
    }

    if (!usersPanel && addBtn) {
      usersPanel =
        addBtn.closest('section') ||
        addBtn.closest('.card') ||
        addBtn.closest('.panel') ||
        addBtn.closest('div');
    }

    if (usersPanel) {
      usersPanel.style.display = 'none';
    }

    const usersTab =
      document.querySelector('[data-view="users"]') ||
      document.querySelector('[data-tab="users"]') ||
      document.getElementById('tabUsers');

    if (usersTab) {
      usersTab.style.display = 'none';
    }
  }

  // OWASP A07 (Identification & Authentication Failures):
  // El botón de logout invalida la sesión en el backend (POST /api/auth/logout)
  // y luego redirige al usuario fuera del panel.
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

// OWASP A05:
// Inicialización controlada del panel solo cuando estamos en la ruta /panel.html.
document.addEventListener('DOMContentLoaded', () => {
  if (location.pathname === '/panel.html') initPanel();
});
