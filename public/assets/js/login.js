// login.js
// Lado cliente para la pantalla de login.
// - Muestra mensajes de bloqueo / error a partir de los parámetros de la URL.
// - Añade validación básica antes de enviar el formulario (OWASP: defensa en profundidad).

document.addEventListener('DOMContentLoaded', () => {
  const msg = document.getElementById('msg');
  const form = document.querySelector('form'); // se asume un único formulario de login en la página

  // ---------------------------------------------------------------------------
  // Mensajes a partir de parámetros de la URL
  // ---------------------------------------------------------------------------
  if (msg) {
    const q = new URLSearchParams(location.search);

    if (q.get('locked') === '1') {
      const w = parseInt(q.get('waitSec') || '0', 10);
      msg.textContent = w > 0
        ? `Cuenta bloqueada temporalmente. Intenta de nuevo en aproximadamente ${Math.ceil(w / 60)} minuto(s).`
        : 'Cuenta bloqueada temporalmente. Intenta nuevamente más adelante.';
    } else if (q.get('error') === '1') {
      const at = parseInt(q.get('attempts') || '0', 10);
      const rem = (3 - (at % 3)) % 3;

      // Mensaje genérico de error de credenciales + info básica de intentos
      msg.textContent =
        `Usuario o contraseña incorrectos. Intentos fallidos acumulados: ${at}` +
        (rem ? ` | El próximo bloqueo ocurrirá en ${rem} intento(s) más.` : '');
    } else {
      msg.textContent = '';
    }
  }

  // ---------------------------------------------------------------------------
  // Validación básica del formulario de login (defensa en profundidad)
  // ---------------------------------------------------------------------------
  if (form && msg) {
    form.addEventListener('submit', (e) => {
      msg.textContent = '';

      const userField = form.elements['username'];
      const passField = form.elements['password'];

      const username = userField ? String(userField.value || '').trim() : '';
      const password = passField ? String(passField.value || '') : '';

      // 1) No permitir envíos vacíos
      if (!username || !password) {
        e.preventDefault();
        msg.textContent = 'Por favor ingrese usuario y contraseña.';
        return;
      }

      // 2) Aviso sobre política de contraseña (no bloquea el envío)
      //    La verificación REAL de seguridad se hace en el backend.
      if (password.length < 8) {
        // No hacemos preventDefault aquí: dejamos que el servidor valide,
        // solo damos una pista al usuario según la política fuerte aplicada en server.js
        msg.textContent = 'Aviso: se recomienda usar contraseñas de al menos 8 caracteres.';
      }
    });
  }
});
