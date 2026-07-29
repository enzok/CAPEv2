"use strict";

const KEYSYM = {
    SHIFT:   0xFFE1,
    CTRL:    0xFFE3,
    INSERT:  0xFF63,
    V_UPPER: 0x0056,
    V_LOWER: 0x0076,
};

const PASTE_DELAY_MS = 50;

const NON_FATAL_STATUS_CODES = new Set([0, 256]);

const ICON_ERROR = 'fas fa-exclamation-circle text-danger';
const ICON_WARNING = 'fas fa-exclamation-triangle text-warning';
const ICON_SUCCESS = 'fas fa-check-circle text-success';

class GuacSession {
    constructor(element, config) {
        this.config = config;
        this.client = null;
        this.tunnel = null;
        this.display = null;
        this.keyboard = null;
        this.input = null;
        this.connected = false;
        this.ctrl = false;
        this.shift = false;
        this.dialogContainer = $(element).find('.guaconsole')[0];
        this.takingSnapshot = false;
        this.remoteClipboard = '';

        this._init();
    }

    _buildWsUrl() {
        return location.origin.replace(/^http(s?):/, (match, p1) =>
            p1 ? 'wss:' : 'ws:'
        );
    }

    _isPasteShortcut(keysym) {
        return (this.ctrl && this.shift && keysym === KEYSYM.V_UPPER)
            || (this.ctrl && keysym === KEYSYM.V_LOWER)
            || (this.shift && keysym === KEYSYM.INSERT);
    }

    _init() {
        const wsUrl = this._buildWsUrl();
        this.tunnel = new Guacamole.WebSocketTunnel(
            wsUrl + '/guac/websocket-tunnel/' + this.config.session_id
        );
        this.client = new Guacamole.Client(this.tunnel);

        this.connect();

        this.display = this.client.getDisplay().getElement();
        $('#terminal').append(this.display);

        this._setupScaling();

        window.onunload = () => this.disconnect();

        this._setupMouse();
        this._setupKeyboard();
        this._setupClipboard();
        this._setupErrorHandler();
    }

    _setupScaling() {
        const scaleDisplay = () => {
            var display = this.client.getDisplay();
            var displayWidth = display.getWidth();
            var displayHeight = display.getHeight();
            if (!displayWidth || !displayHeight) return;

            var container = document.getElementById('container');
            var containerWidth = container.offsetWidth;
            var containerHeight = container.offsetHeight;
            if (!containerWidth || !containerHeight) return;

            var scale = Math.min(
                containerWidth / displayWidth,
                containerHeight / displayHeight
            );
            display.scale(scale);
        };

        this.client.getDisplay().onresize = function() {
            scaleDisplay();
        };

        var resizeTimeout;
        window.addEventListener('resize', function() {
            clearTimeout(resizeTimeout);
            resizeTimeout = setTimeout(scaleDisplay, 100);
        });
    }

    _setupMouse() {
        const mouse = new Guacamole.Mouse(this.display);
        const sendState = (state) => this.client.sendMouseState(state, true);
        mouse.onmousedown = sendState;
        mouse.onmouseup   = sendState;
        mouse.onmousemove = sendState;
    }

    // Browsers only dispatch `paste` at an EDITABLE target, so keyboard focus cannot live on the
    // Guacamole display (a plain div): a hidden textarea holds it instead. Guacamole.Keyboard reads
    // its key events, and because onkeydown lets a real paste combo through, the browser delivers a
    // genuine paste event here for _setupClipboard to forward to the guest. Every other key is
    // preventDefault()ed, so nothing is ever actually inserted.
    _createInputSink() {
        return $('<textarea>')
            .attr({ 'aria-hidden': 'true', tabindex: -1, autocomplete: 'off' })
            // position:fixed (not a negative margin/left) so focusing it can never scroll the page.
            .css({
                position: 'fixed', top: 0, left: 0, width: '1px', height: '1px',
                opacity: 0, border: 0, padding: 0, resize: 'none', zIndex: -1,
            })
            .appendTo('body');
    }

    _focusInput() {
        const x = window.scrollX, y = window.scrollY;
        this.input.focus();
        window.scrollTo(x, y);
    }

    _setupKeyboard() {
        this.input = this._createInputSink();
        this.keyboard = new Guacamole.Keyboard(this.input[0]);

        this.keyboard.onkeydown = (keysym) => {
            if (keysym === KEYSYM.SHIFT)  this.shift = true;
            else if (keysym === KEYSYM.CTRL) this.ctrl = true;

            if (this._isPasteShortcut(keysym)) {
                setTimeout(() => this.client.sendKeyEvent(1, keysym), PASTE_DELAY_MS);
            } else {
                this.client.sendKeyEvent(1, keysym);
            }

            // Guacamole.Keyboard computes defaultPrevented = !onkeydown(keysym) and calls
            // preventDefault() when that is true, so returning TRUE lets the browser act on the key.
            // Only an actual paste combo needs that -- it is what makes the browser fire its own paste
            // event at the input sink. Everything else must be swallowed: Tab would move focus off to
            // the toolbar controls, and any other key would be INSERTED into the sink textarea, whose
            // input event Guacamole.Keyboard turns into a second, duplicate keystroke. Note the
            // modifiers are matched bare while V/Insert are matched only in combination, so plain "v"
            // is swallowed like any other character.
            return this._isPasteShortcut(keysym)
                || keysym === KEYSYM.CTRL
                || keysym === KEYSYM.SHIFT;
        };

        this.keyboard.onkeyup = (keysym) => {
            if (keysym === KEYSYM.SHIFT)  this.shift = false;
            else if (keysym === KEYSYM.CTRL) this.ctrl = false;

            if (this._isPasteShortcut(keysym)) {
                setTimeout(() => this.client.sendKeyEvent(0, keysym), PASTE_DELAY_MS);
            } else {
                this.client.sendKeyEvent(0, keysym);
            }
        };

        // Focus still follows the pointer over the guest image, but the sink is what holds it, so the
        // display must NOT carry a tabindex any more -- being focusable would let a click move focus
        // off the sink and silently kill the keyboard.
        $(this.display).hover(
            () => this._focusInput(),
            () => this.input.blur()
        );
        this.input.on('blur', () => this.keyboard.reset());

        // Hover alone cannot always give focus back: no mouseenter fires while the pointer sits
        // still, and _setupScaling letterboxes the display inside #container, so the bars around the
        // guest image are not the display element. Bind on #container -- display clicks bubble to it,
        // so one handler covers image and bars both. preventDefault stops the browser moving focus to
        // <body> on the way, which would otherwise blur the sink and reset the keyboard on every
        // click; Guacamole.Mouse has already handled the event by this point. Modals blur it too.
        $('#container').on('mousedown', (e) => {
            e.preventDefault();
            this._focusInput();
        });
        $(document).on('hidden.bs.modal', '.modal', () => this._focusInput());
    }

    sendClipboard(text) {
        if (!text || !this.connected) return;
        const writer = new Guacamole.StringWriter(
            this.client.createClipboardStream('text/plain')
        );
        writer.sendText(text);
        writer.sendEnd();
    }

    _setupClipboard() {
        // Host -> VM. The paste lands on the input sink, the only editable target in play -- a
        // document-level handler gated on the display div never fires, because browsers do not
        // dispatch `paste` at non-editable elements. preventDefault keeps the sink empty; the guest
        // receives the text via its own clipboard and the Ctrl+V that _setupKeyboard delays by
        // PASTE_DELAY_MS then makes it paste.
        this.input.on('paste', (e) => {
            e.preventDefault();
            this.sendClipboard(e.originalEvent.clipboardData.getData('text/plain'));
        });

        // VM -> host. Cached for the clipboard panel, and pushed straight to the host clipboard when
        // the browser permits it -- navigator.clipboard needs a secure context, so plain-HTTP
        // deployments fall back to the panel's copy button (a click supplies the required gesture).
        this.client.onclipboard = (stream, mimetype) => {
            if (!mimetype.startsWith('text/')) return;
            const reader = new Guacamole.StringReader(stream);
            let data = '';
            reader.ontext = (text) => { data += text; };
            reader.onend = () => {
                this.remoteClipboard = data;
                if (window.isSecureContext && navigator.clipboard) {
                    navigator.clipboard.writeText(data).catch(() => {});
                }
            };
        };
    }

    _showDialog(title, detail, icon) {
        const dialog = $('#launch_error');
        const iconHtml = icon ? `<i class="${icon} me-1"></i>` : '';
        dialog.find('#dialog-heading').html(`${iconHtml}${title}`);
        dialog.find('#dialog-message').html(detail);
        dialog.dialog({ dialogClass: 'no-close' });
        dialog.dialog(this.dialogContainer);
    }

    _showError(title, detail) {
        this._showDialog(title, detail, ICON_ERROR);
    }

    _showWarning(title, detail) {
        this._showDialog(title, detail, ICON_WARNING);
    }

    _showSuccess(title, detail) {
        this._showDialog(title, detail, ICON_SUCCESS);
    }

    _setupErrorHandler() {
        const handler = (error) => {
            console.log(`guac error ${error.code}: ${error.message}`);

            if (this.takingSnapshot) {
                console.log("Ignoring guac error during snapshot");
                return;
            }

            if (NON_FATAL_STATUS_CODES.has(error.code)) {
                return;
            }

            this.disconnect();

            if (error.code === 514) {
                this._showError("Connection error", "Server timeout.");
            } else if (error.code === 515) {
                this._showSuccess("Session complete", "Backing VM has disconnected.");
            } else if (error.code === 522) {
                this._showWarning("Session ended", "Session timed out due to inactivity.");
            } else {
                const _msg = `An unexpected error occurred: ${error.message}`;
                this._showError("Connection error", _msg);
            }
        };

        this.tunnel.onerror = handler;
        this.client.onerror = handler;
    }

    connect() {
        if (this.connected) {
            this.client.disconnect();
            this.connected = false;
        }

        try {
            this.client.connect($.param({
                'recording_name': this.config.recording_name,
            }));
            this.connected = true;
        } catch (e) {
            console.warn(e);
            this.connected = false;
            throw e;
        }
    }

    disconnect() {
        if (this.connected) {
            this.client.disconnect();
            this.connected = false;
        }
    }
}

function GuacMe(element, session_id, recording_name) {
    return new GuacSession(element, { session_id, recording_name });
}

function getCsrfToken() {
    var match = document.cookie.match(/csrftoken=([^;]+)/);
    return match ? match[1] : '';
}

function stopTask(taskId, onSuccess, onError) {
    var btn = document.getElementById('stopTask');
    if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Stopping...'; }
  
    const apiUrl = location.origin + "/apiv2/tasks/status/" + taskId + "/";

    fetch(apiUrl, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCsrfToken(),
        },
        body: JSON.stringify({ status: 'finish' }),
    })
    .then(response => response.json())
    .then(data => {
        console.log('Response:', data);
        if (onSuccess) onSuccess(data);
        location.replace(location.origin + '/submit/status/' + taskId + '/');
    })
    .catch(error => {
        console.error('Error:', error);
        if (onError) onError(error);
        if (btn) { btn.disabled = false; btn.innerHTML = '<i class="fas fa-stop-circle me-1"></i>End Session'; }
    });
}
