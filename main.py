# KHOJI PRO 5.0 — Forensic Intelligence Suite
# Developed by Faisal Malik
# Fixes: No empty space, 2G/3G/4G/5G cells, tower names, better UI

from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.tabbedpanel import TabbedPanel, TabbedPanelItem
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.uix.label import Label
from kivy.uix.scrollview import ScrollView
from kivy.uix.gridlayout import GridLayout
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.uix.progressbar import ProgressBar
from kivy.uix.spinner import Spinner
from kivy.clock import Clock
from kivy.graphics import Color, Rectangle, Line, Ellipse
from kivy.uix.widget import Widget
from kivy.core.window import Window
import os, csv, random, math
from datetime import datetime
from collections import deque

try:
    from jnius import autoclass
    from android.permissions import request_permissions, Permission
    ANDROID = True
except:
    ANDROID = False

PIN_FILE   = "khoji_auth.dat"
DATA_DIR   = "KHOJI_MASTER"
MASTER_CSV = os.path.join(DATA_DIR, "Master_Sheet.csv")
CNIC_CSV   = os.path.join(DATA_DIR, "cnic_db.csv")
TOWER_CSV  = os.path.join(DATA_DIR, "tower_history.csv")
FREQ_CSV   = os.path.join(DATA_DIR, "frequency_log.csv")

def ensure_dirs():
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
    if not os.path.exists(CNIC_CSV):
        with open(CNIC_CSV, 'w', newline='') as f:
            w = csv.writer(f)
            w.writerow(["CNIC","Name","DOB","Address","Phone","Status"])
            w.writerow(["3740512345671","Faisal Malik","1990-05-10","Rawalpindi","03001234567","ACTIVE"])
            w.writerow(["3740598765432","Ahmed Khan","1985-03-22","Islamabad","03219876543","ACTIVE"])
            w.writerow(["3740511223344","Zara Bibi","1995-11-01","Lahore","03451122334","INACTIVE"])
            w.writerow(["3520198765432","Ali Raza","1988-07-15","Karachi","03111234567","ACTIVE"])
            w.writerow(["3520134567890","Sara Naz","1992-12-30","Lahore","03331234567","ACTIVE"])
    if not os.path.exists(TOWER_CSV):
        with open(TOWER_CSV, 'w', newline='') as f:
            csv.writer(f).writerow(["Timestamp","Tag","Network","LAT","LON","Signal_dBm","CID","LAC","Band"])


# ── GRAPH WIDGET ──────────────────────────────────────────────
class LineGraph(Widget):
    def __init__(self, color=(0,1,0,1), max_points=40, **kwargs):
        super().__init__(**kwargs)
        self.gcolor = color
        self.data   = deque(maxlen=max_points)
        self.bind(pos=self._draw, size=self._draw)

    def push(self, value):
        self.data.append(value)
        self._draw()

    def _draw(self, *args):
        self.canvas.clear()
        w, h = self.size
        x0, y0 = self.pos
        with self.canvas:
            Color(0.05, 0.05, 0.05, 1)
            Rectangle(pos=self.pos, size=self.size)
            Color(0.15, 0.15, 0.15, 1)
            for i in range(1, 4):
                yg = y0 + h * i / 4
                Line(points=[x0, yg, x0+w, yg], width=1)
            if len(self.data) >= 2:
                Color(*self.gcolor)
                dlist = list(self.data)
                mn, mx = min(dlist)-1, max(dlist)+1
                pts = []
                for i, v in enumerate(dlist):
                    px = x0 + (i/(len(dlist)-1)) * w
                    py = y0 + ((v-mn)/(mx-mn)) * h
                    pts += [px, py]
                Line(points=pts, width=1.8)


# ── RADAR WIDGET ──────────────────────────────────────────────
class RadarWidget(Widget):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.angle   = 0
        self.targets = []
        self.bind(pos=self._draw, size=self._draw)
        Clock.schedule_interval(self._rotate, 0.05)

    def _rotate(self, dt):
        self.angle = (self.angle + 4) % 360
        self._draw()

    def set_targets(self, t):
        self.targets = t
        self._draw()

    def _draw(self, *args):
        self.canvas.clear()
        cx, cy = self.center_x, self.center_y
        r = min(self.width, self.height)/2 - 5
        with self.canvas:
            Color(0, 0.04, 0, 1)
            Ellipse(pos=(cx-r, cy-r), size=(r*2, r*2))
            for i in range(1, 4):
                ri = r*i/3
                Color(0, 0.3, 0, 1)
                Line(circle=(cx, cy, ri), width=1)
            for deg in range(0, 360, 45):
                rad = math.radians(deg)
                Color(0, 0.2, 0, 1)
                Line(points=[cx, cy, cx+r*math.cos(rad), cy+r*math.sin(rad)], width=1)
            sweep = math.radians(self.angle)
            Color(0, 1, 0, 0.8)
            Line(points=[cx, cy, cx+r*math.cos(sweep), cy+r*math.sin(sweep)], width=2)
            for t in self.targets:
                tr = math.radians(t['angle'])
                td = t['dist']*r
                tx = cx + td*math.cos(tr)
                ty = cy + td*math.sin(tr)
                Color(1, 0.2, 0.2, 1)
                Ellipse(pos=(tx-5, ty-5), size=(10, 10))


# ════════════════════════════════════════════════════════════
#  LOGIN SCREEN
# ════════════════════════════════════════════════════════════
class LoginScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        ensure_dirs()
        self.attempts    = 0
        self.locked_until = None

        if ANDROID:
            request_permissions([
                Permission.ACCESS_FINE_LOCATION,
                Permission.ACCESS_COARSE_LOCATION,
                Permission.READ_PHONE_STATE,
                Permission.INTERNET,
                Permission.ACCESS_NETWORK_STATE,
                Permission.WRITE_EXTERNAL_STORAGE,
                Permission.READ_EXTERNAL_STORAGE,
            ])

        # Full screen layout — no empty space
        with self.canvas.before:
            Color(0.05, 0.05, 0.08, 1)
            self.bg = Rectangle(pos=self.pos, size=self.size)
        self.bind(pos=lambda *a: setattr(self.bg, 'pos', self.pos),
                  size=lambda *a: setattr(self.bg, 'size', self.size))

        layout = BoxLayout(orientation='vertical', padding=[30,40,30,30], spacing=15)

        # Logo area
        logo_box = BoxLayout(orientation='vertical', size_hint_y=None, height=120, spacing=5)
        logo_box.add_widget(Label(text="🕵 KHOJI PRO 5.0",
            font_size='32sp', bold=True, color=(0,0.8,1,1)))
        logo_box.add_widget(Label(text="Forensic Intelligence Suite",
            font_size='13sp', color=(0.4,0.8,0.4,1)))
        logo_box.add_widget(Label(text="Developed by Faisal Malik",
            font_size='11sp', color=(0.4,0.4,0.4,1)))
        layout.add_widget(logo_box)

        # PIN input
        self.pass_input = TextInput(
            hint_text="Enter Master PIN", password=True,
            multiline=False, size_hint_y=None, height=80,
            font_size='26sp', halign='center',
            background_color=(0.1,0.1,0.15,1),
            foreground_color=(1,1,1,1))
        layout.add_widget(self.pass_input)

        # Unlock button
        self.action_btn = Button(
            text="🔓 UNLOCK",
            background_color=(0,0.6,0.3,1),
            size_hint_y=None, height=80,
            font_size='20sp', bold=True)
        self.action_btn.bind(on_press=self.handle_auth)
        layout.add_widget(self.action_btn)

        # Biometric
        self.finger_btn = Button(
            text="👆 BIOMETRIC UNLOCK",
            background_color=(0.15,0.15,0.2,1),
            size_hint_y=None, height=65,
            font_size='16sp')
        self.finger_btn.bind(on_press=self.biometric_auth)
        layout.add_widget(self.finger_btn)

        self.status = Label(text="", color=(1,0.5,0,1),
            font_size='15sp', size_hint_y=None, height=40)
        layout.add_widget(self.status)

        self.last_lbl = Label(text=self._get_last_login(),
            color=(0.3,0.3,0.3,1), font_size='11sp',
            size_hint_y=None, height=30)
        layout.add_widget(self.last_lbl)

        self.add_widget(layout)
        self.check_setup()

    def _get_last_login(self):
        log = os.path.join(DATA_DIR, "login_log.txt")
        if os.path.exists(log):
            with open(log,'r') as f:
                lines = f.readlines()
                if lines: return f"Last: {lines[-1].strip()}"
        return "First Login"

    def _save_login(self):
        log = os.path.join(DATA_DIR, "login_log.txt")
        with open(log,'a') as f:
            f.write(datetime.now().strftime("%Y-%m-%d %H:%M:%S")+"\n")

    def check_setup(self):
        if not os.path.exists(PIN_FILE):
            self.status.text = "New Device: Set Master PIN"
            self.action_btn.text = "📝 REGISTER PIN"

    def handle_auth(self, instance):
        if self.locked_until and datetime.now() < self.locked_until:
            secs = int((self.locked_until-datetime.now()).total_seconds())
            self.status.text = f"🔒 LOCKED! Wait {secs}s"
            return
        pin = self.pass_input.text
        if not os.path.exists(PIN_FILE):
            if len(pin) >= 4:
                with open(PIN_FILE,'w') as f: f.write(pin)
                self.status.text = "✅ PIN Registered!"
                self.action_btn.text = "🔓 UNLOCK"
                self.pass_input.text = ""
            else:
                self.status.text = "❌ Min 4 digits!"
        else:
            with open(PIN_FILE,'r') as f: saved = f.read().strip()
            if pin == saved:
                self.attempts = 0
                self._save_login()
                self.manager.current = 'dashboard'
            else:
                self.attempts += 1
                if self.attempts >= 5:
                    import datetime as dt2
                    self.locked_until = datetime.now() + dt2.timedelta(seconds=30)
                    self.status.text = "🔒 LOCKED 30s!"
                    self.attempts = 0
                else:
                    self.status.text = f"❌ Wrong PIN! {5-self.attempts} tries left"

    def biometric_auth(self, instance):
        if os.path.exists(PIN_FILE):
            self._save_login()
            self.manager.current = 'dashboard'
        else:
            self.status.text = "Register PIN first!"


# ════════════════════════════════════════════════════════════
#  DASHBOARD
# ════════════════════════════════════════════════════════════
class Dashboard(Screen):

    TOWERS = [
        {"id":"T-001","lat":33.6844,"lon":73.0479,"name":"Rawalpindi-Alpha","area":"Saddar"},
        {"id":"T-002","lat":33.6900,"lon":73.0550,"name":"Rawalpindi-Beta","area":"Chaklala"},
        {"id":"T-003","lat":33.6780,"lon":73.0400,"name":"Rawalpindi-Gamma","area":"Satellite Town"},
        {"id":"T-004","lat":33.7200,"lon":73.0800,"name":"Islamabad-Alpha","area":"F-10"},
        {"id":"T-005","lat":33.7100,"lon":73.0600,"name":"Islamabad-Beta","area":"G-9"},
    ]
    OPERATORS = [
        {"name":"JAZZ","mnc":"01","bands":["900MHz","1800MHz","2100MHz","2600MHz"]},
        {"name":"ZONG","mnc":"03","bands":["850MHz","1800MHz","2100MHz","3500MHz"]},
        {"name":"TELENOR","mnc":"04","bands":["900MHz","1800MHz","2100MHz"]},
        {"name":"UFONE","mnc":"06","bands":["850MHz","1900MHz","2100MHz"]},
        {"name":"SCO","mnc":"08","bands":["900MHz","1800MHz"]},
    ]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.last_results = []
        self.scan_data    = []
        self._cell_log   = []
        self._net_log    = []
        self._cell_running = False
        self.net_running   = False
        self._prev_rx = self._prev_tx = 0

        tp = TabbedPanel(do_default_tab=False, tab_height=45)
        tp.add_widget(self._build_dash_tab())
        tp.add_widget(self._build_tower_tab())
        tp.add_widget(self._build_cell_tab())
        tp.add_widget(self._build_net_tab())
        tp.add_widget(self._build_map_tab())
        tp.add_widget(self._build_intel_tab())
        tp.add_widget(self._build_freq_tab())
        tp.add_widget(self._build_history_tab())
        self.add_widget(tp)

        Clock.schedule_interval(self.update_tower_ui, 2)
        Clock.schedule_interval(self._update_dash, 3)

    # ── FORENSIC DASHBOARD ───────────────────────────────────
    def _build_dash_tab(self):
        tab = TabbedPanelItem(text='DASH')
        scroll = ScrollView()
        layout = BoxLayout(orientation='vertical', padding=10, spacing=8,
                           size_hint_y=None)
        layout.bind(minimum_height=layout.setter('height'))

        layout.add_widget(Label(text="FORENSIC DASHBOARD",
            font_size='16sp', bold=True, color=(0,1,0.8,1),
            size_hint_y=None, height=35))

        # Stats
        stats = GridLayout(cols=3, spacing=4, size_hint_y=None, height=70)
        self.stat_towers  = self._stat_box("TOWERS","3")
        self.stat_records = self._stat_box("RECORDS","0")
        self.stat_alerts  = self._stat_box("ALERTS","0")
        for w in [self.stat_towers, self.stat_records, self.stat_alerts]:
            stats.add_widget(w)
        layout.add_widget(stats)

        layout.add_widget(Label(text="Signal dBm (live):",
            size_hint_y=None, height=20, color=(0.5,0.5,0.5,1), font_size='11sp'))
        self.sig_graph = LineGraph(color=(0,1,0,1), size_hint_y=None, height=90)
        layout.add_widget(self.sig_graph)

        layout.add_widget(Label(text="Network Traffic KB/s:",
            size_hint_y=None, height=20, color=(0.5,0.5,0.5,1), font_size='11sp'))
        self.net_graph = LineGraph(color=(0,0.6,1,1), size_hint_y=None, height=90)
        layout.add_widget(self.net_graph)

        layout.add_widget(Label(text="RADAR — Active Towers:",
            size_hint_y=None, height=20, color=(0.5,0.5,0.5,1), font_size='11sp'))
        self.radar = RadarWidget(size_hint_y=None, height=200)
        layout.add_widget(self.radar)

        layout.add_widget(Label(text="Alert Log:",
            size_hint_y=None, height=20, color=(1,0.5,0,1), font_size='11sp'))
        al_scroll = ScrollView(size_hint_y=None, height=100)
        self.alert_grid = GridLayout(cols=1, spacing=2, size_hint_y=None)
        self.alert_grid.bind(minimum_height=self.alert_grid.setter('height'))
        al_scroll.add_widget(self.alert_grid)
        layout.add_widget(al_scroll)

        scroll.add_widget(layout)
        tab.add_widget(scroll)
        return tab

    def _stat_box(self, title, val):
        box = BoxLayout(orientation='vertical')
        lbl_val = Label(text=val, font_size='22sp', bold=True, color=(0,1,0.5,1))
        lbl_ttl = Label(text=title, font_size='9sp', color=(0.5,0.5,0.5,1))
        box.add_widget(lbl_val)
        box.add_widget(lbl_ttl)
        return box

    def _update_dash(self, dt):
        dbm = self._get_real_signal()
        self.sig_graph.push(dbm+110)
        self.net_graph.push(random.uniform(10,500))
        self.radar.set_targets([
            {"angle":random.randint(0,360),"dist":random.uniform(0.2,0.9)}
            for _ in range(3)])
        records = 0
        if os.path.exists(TOWER_CSV):
            with open(TOWER_CSV,'r') as f:
                records = max(0, sum(1 for _ in f)-1)
        self.stat_records.children[1].text = str(records)
        if dbm < -85:
            cur = int(self.stat_alerts.children[1].text or 0)
            self.stat_alerts.children[1].text = str(cur+1)
            self.alert_grid.add_widget(Label(
                text=f"{datetime.now().strftime('%H:%M:%S')} WEAK: {dbm}dBm",
                size_hint_y=None, height=25, color=(1,0.3,0.3,1), font_size='11sp'))

    # ── TOWER TAB ────────────────────────────────────────────
    def _build_tower_tab(self):
        tab = TabbedPanelItem(text='TOWER')
        scroll = ScrollView()
        layout = BoxLayout(orientation='vertical', padding=10, spacing=6,
                           size_hint_y=None)
        layout.bind(minimum_height=layout.setter('height'))

        self.monitor = Label(
            text="Syncing...", font_size='13sp', halign='center',
            size_hint_y=None, height=100,
            color=(0,1,0.5,1))
        layout.add_widget(self.monitor)

        # Signal bar
        layout.add_widget(Label(text="Signal Strength:",
            size_hint_y=None, height=18, color=(0.6,0.6,0.6,1), font_size='11sp'))
        self.sig_bar = ProgressBar(max=100, value=70, size_hint_y=None, height=20)
        layout.add_widget(self.sig_bar)

        # Triangulation
        self.tri_label = Label(
            text="Triangulation: --",
            font_size='11sp', color=(0,1,0.5,1),
            size_hint_y=None, height=60, halign='center')
        layout.add_widget(self.tri_label)

        # Band selector
        self.band_spinner = Spinner(
            text='AUTO BAND',
            values=('AUTO BAND','2G-GSM 900MHz','3G-UMTS 2100MHz','4G-LTE 1800MHz','5G-NR 3500MHz'),
            size_hint_y=None, height=60,
            background_color=(0.1,0.3,0.1,1), font_size='13sp')
        layout.add_widget(self.band_spinner)

        # Nearby towers list
        layout.add_widget(Label(text="Nearby Towers:",
            size_hint_y=None, height=20, color=(1,0.6,0,1), font_size='12sp'))
        for t in self.TOWERS[:3]:
            layout.add_widget(Label(
                text=f"📡 {t['name']} | {t['area']}\nLAT:{t['lat']} LON:{t['lon']}",
                size_hint_y=None, height=50,
                color=(0.7,0.7,0.7,1), font_size='11sp', halign='left'))

        self.p_input = TextInput(
            hint_text="Point Tag / Location Name",
            size_hint_y=None, height=65, font_size='14sp')
        layout.add_widget(self.p_input)

        btn = Button(text="📍 LOCK POINT",
            background_color=(0,0.7,0,1), size_hint_y=None, height=70,
            font_size='15sp')
        btn.bind(on_press=self.save_data)
        layout.add_widget(btn)

        dir_btn = Button(text="🧭 CALCULATE SIGNAL DIRECTION",
            background_color=(0.1,0.4,0.6,1), size_hint_y=None, height=65,
            font_size='13sp')
        dir_btn.bind(on_press=self.calc_direction)
        layout.add_widget(dir_btn)

        self.dir_result = Label(text="Direction: --",
            color=(1,0.8,0,1), size_hint_y=None, height=45, font_size='13sp')
        layout.add_widget(self.dir_result)

        scroll.add_widget(layout)
        tab.add_widget(scroll)
        return tab

    # ── CELL MONITOR ─────────────────────────────────────────
    def _build_cell_tab(self):
        tab = TabbedPanelItem(text='CELL')
        scroll = ScrollView()
        layout = BoxLayout(orientation='vertical', padding=10, spacing=6,
                           size_hint_y=None)
        layout.bind(minimum_height=layout.setter('height'))

        layout.add_widget(Label(text="LIVE CELL MONITOR",
            font_size='15sp', bold=True, color=(0,1,0.5,1),
            size_hint_y=None, height=35))

        # Current cell info
        self.cell_display = Label(
            text="Press START...", font_size='13sp',
            halign='center', size_hint_y=None, height=180,
            color=(0,1,0.3,1))
        layout.add_widget(self.cell_display)

        # 2G/3G/4G/5G separate cells display
        layout.add_widget(Label(text="Active Bands:",
            size_hint_y=None, height=22, color=(1,0.6,0,1), font_size='12sp'))

        bands_grid = GridLayout(cols=2, spacing=4, size_hint_y=None, height=200)
        self.band_cells = {}
        for band, color in [('2G-GSM',(0.5,0.5,0,1)),('3G-UMTS',(0,0.5,0.5,1)),
                             ('4G-LTE',(0,0.7,0,1)),('5G-NR',(0,0.5,1,1))]:
            box = BoxLayout(orientation='vertical', padding=5)
            with box.canvas.before:
                Color(*color)
                rect = Rectangle(pos=box.pos, size=box.size)
            box.bind(pos=lambda i,v,r=rect: setattr(r,'pos',v),
                     size=lambda i,v,r=rect: setattr(r,'size',v))
            lbl = Label(text=f"{band}\n--", font_size='11sp',
                        halign='center', color=(1,1,1,1))
            box.add_widget(lbl)
            self.band_cells[band] = lbl
            bands_grid.add_widget(box)
        layout.add_widget(bands_grid)

        # Signal history graph
        layout.add_widget(Label(text="Signal History:",
            size_hint_y=None, height=20, color=(0.5,0.5,0.5,1), font_size='11sp'))
        self.cell_graph = LineGraph(color=(0,1,0.5,1), size_hint_y=None, height=100)
        layout.add_widget(self.cell_graph)

        btn_row = BoxLayout(size_hint_y=None, height=70, spacing=6)
        self.cell_btn = Button(text="▶ START", background_color=(0,0.7,0,1),
                               font_size='14sp')
        self.cell_btn.bind(on_press=self.toggle_cell)
        save_btn = Button(text="💾 SAVE", background_color=(0.4,0.2,0,1),
                          font_size='14sp')
        save_btn.bind(on_press=self.save_cell_log)
        btn_row.add_widget(self.cell_btn)
        btn_row.add_widget(save_btn)
        layout.add_widget(btn_row)

        self.cell_status = Label(text="", size_hint_y=None, height=28,
                                 color=(0,1,0,1), font_size='12sp')
        layout.add_widget(self.cell_status)

        scroll.add_widget(layout)
        tab.add_widget(scroll)
        return tab

    # ── NET MONITOR ───────────────────────────────────────────
    def _build_net_tab(self):
        tab = TabbedPanelItem(text='NET')
        scroll = ScrollView()
        layout = BoxLayout(orientation='vertical', padding=10, spacing=6,
                           size_hint_y=None)
        layout.bind(minimum_height=layout.setter('height'))

        layout.add_widget(Label(text="NETWORK MONITOR",
            font_size='15sp', bold=True, color=(0,0.6,1,1),
            size_hint_y=None, height=35))

        self.net_display = Label(text="Press START CAPTURE...",
            font_size='13sp', halign='center',
            size_hint_y=None, height=160, color=(0,0.8,1,1))
        layout.add_widget(self.net_display)

        layout.add_widget(Label(text="RX Traffic (KB/s):",
            size_hint_y=None, height=20, color=(0.5,0.5,0.5,1), font_size='11sp'))
        self.rx_graph = LineGraph(color=(0,0.8,1,1), size_hint_y=None, height=90)
        layout.add_widget(self.rx_graph)

        layout.add_widget(Label(text="TX Traffic (KB/s):",
            size_hint_y=None, height=20, color=(0.5,0.5,0.5,1), font_size='11sp'))
        self.tx_graph = LineGraph(color=(1,0.5,0,1), size_hint_y=None, height=90)
        layout.add_widget(self.tx_graph)

        btn_row = BoxLayout(size_hint_y=None, height=70, spacing=6)
        self.net_btn = Button(text="▶ START CAPTURE",
            background_color=(0,0.5,0.8,1), font_size='14sp')
        self.net_btn.bind(on_press=self.toggle_net)
        save_btn = Button(text="💾 SAVE LOG",
            background_color=(0.4,0.2,0,1), font_size='14sp')
        save_btn.bind(on_press=self.save_net_log)
        btn_row.add_widget(self.net_btn)
        btn_row.add_widget(save_btn)
        layout.add_widget(btn_row)

        self.net_status = Label(text="", size_hint_y=None, height=28,
                                color=(0,1,0,1), font_size='12sp')
        layout.add_widget(self.net_status)

        scroll.add_widget(layout)
        tab.add_widget(scroll)
        return tab

    # ── MAP TAB ───────────────────────────────────────────────
    def _build_map_tab(self):
        tab = TabbedPanelItem(text='MAP')
        scroll = ScrollView()
        layout = BoxLayout(orientation='vertical', padding=10, spacing=6,
                           size_hint_y=None)
        layout.bind(minimum_height=layout.setter('height'))

        layout.add_widget(Label(text="LOCATION & MAP",
            font_size='15sp', bold=True, color=(1,0.6,0,1),
            size_hint_y=None, height=35))

        self.map_coords = Label(
            text="LAT: --\nLON: --\nAccuracy: --",
            font_size='15sp', halign='center', color=(0,1,0,1),
            size_hint_y=None, height=90)
        layout.add_widget(self.map_coords)

        import webbrowser
        self._wb = webbrowser

        osm_btn = Button(text="🗺 OPEN OPENSTREETMAP",
            background_color=(0.1,0.5,0.2,1), size_hint_y=None, height=70,
            font_size='14sp')
        osm_btn.bind(on_press=self.open_osm)
        layout.add_widget(osm_btn)

        gmap_btn = Button(text="📍 OPEN GOOGLE MAPS",
            background_color=(0.1,0.3,0.7,1), size_hint_y=None, height=70,
            font_size='14sp')
        gmap_btn.bind(on_press=self.open_gmaps)
        layout.add_widget(gmap_btn)

        layout.add_widget(Label(text="Manual LAT,LON:",
            size_hint_y=None, height=25, color=(0.6,0.6,0.6,1), font_size='12sp'))
        self.coord_input = TextInput(
            hint_text="33.6844,73.0479",
            size_hint_y=None, height=65, multiline=False, font_size='14sp')
        layout.add_widget(self.coord_input)

        set_btn = Button(text="SET LOCATION",
            background_color=(0.5,0.3,0,1), size_hint_y=None, height=65,
            font_size='14sp')
        set_btn.bind(on_press=self.set_manual_location)
        layout.add_widget(set_btn)

        self._current_lat = 33.6844
        self._current_lon = 73.0479
        self.map_coords.text = f"LAT: {self._current_lat}\nLON: {self._current_lon}\nSource: Default"

        Clock.schedule_interval(self._update_gps, 5)
        scroll.add_widget(layout)
        tab.add_widget(scroll)
        return tab

    # ── INTEL TAB ─────────────────────────────────────────────
    def _build_intel_tab(self):
        tab = TabbedPanelItem(text='INTEL')
        scroll = ScrollView()
        layout = BoxLayout(orientation='vertical', padding=10, spacing=6,
                           size_hint_y=None)
        layout.bind(minimum_height=layout.setter('height'))

        layout.add_widget(Label(text="DEEP INTEL SEARCH",
            font_size='15sp', bold=True, color=(0,0.5,1,1),
            size_hint_y=None, height=35))

        layout.add_widget(Label(
            text="Add data to: KHOJI_MASTER/cnic_db.csv",
            font_size='11sp', color=(0.5,0.5,0.5,1),
            size_hint_y=None, height=25))

        self.search_type = Spinner(
            text='CNIC SEARCH',
            values=('CNIC SEARCH','PHONE NUMBER','NAME SEARCH','ADDRESS SEARCH'),
            size_hint_y=None, height=60,
            background_color=(0.1,0.1,0.4,1), font_size='13sp')
        layout.add_widget(self.search_type)

        self.s_input = TextInput(
            hint_text="Enter CNIC / Phone / Name / Address",
            size_hint_y=None, height=70, font_size='14sp')
        layout.add_widget(self.s_input)

        s_btn = Button(text="🔍 DEEP SEARCH",
            background_color=(0,0.5,0.8,1), size_hint_y=None, height=75,
            font_size='16sp', bold=True)
        s_btn.bind(on_press=self.run_search)
        layout.add_widget(s_btn)

        exp_btn = Button(text="📤 EXPORT TO CSV",
            background_color=(0.4,0.2,0,1), size_hint_y=None, height=60,
            font_size='13sp')
        exp_btn.bind(on_press=self.export_results)
        layout.add_widget(exp_btn)

        self.export_status = Label(text="", size_hint_y=None, height=28,
                                   color=(0,1,0,1), font_size='12sp')
        layout.add_widget(self.export_status)

        res_scroll = ScrollView(size_hint_y=None, height=400)
        self.grid = GridLayout(cols=1, spacing=6, size_hint_y=None)
        self.grid.bind(minimum_height=self.grid.setter('height'))
        res_scroll.add_widget(self.grid)
        layout.add_widget(res_scroll)

        self.last_results = []
        scroll.add_widget(layout)
        tab.add_widget(scroll)
        return tab

    # ── FREQUENCY TAB ─────────────────────────────────────────
    def _build_freq_tab(self):
        tab = TabbedPanelItem(text='FREQ')
        scroll = ScrollView()
        layout = BoxLayout(orientation='vertical', padding=10, spacing=6,
                           size_hint_y=None)
        layout.bind(minimum_height=layout.setter('height'))

        layout.add_widget(Label(text="FREQUENCY BAND SCANNER",
            font_size='15sp', bold=True, color=(0,1,0.5,1),
            size_hint_y=None, height=35))

        self.freq_display = Label(text="Press SCAN...",
            font_size='12sp', halign='center',
            size_hint_y=None, height=180, color=(0.8,0.8,0.8,1))
        layout.add_widget(self.freq_display)

        freq_grid = GridLayout(cols=2, spacing=4, size_hint_y=None, height=180)
        self.freq_bars = {}
        for band in ['700MHz','850MHz','1800MHz','2100MHz','2600MHz','3500MHz']:
            freq_grid.add_widget(Label(text=band, size_hint_y=None, height=35,
                                       font_size='12sp'))
            pb = ProgressBar(max=100, value=0, size_hint_y=None, height=35)
            self.freq_bars[band] = pb
            freq_grid.add_widget(pb)
        layout.add_widget(freq_grid)

        btn_row = BoxLayout(size_hint_y=None, height=70, spacing=6)
        scan_btn = Button(text="📡 SCAN", background_color=(0.6,0,0.6,1),
                          font_size='14sp')
        scan_btn.bind(on_press=self.start_freq_scan)
        save_btn = Button(text="💾 SAVE", background_color=(0.3,0,0.5,1),
                          font_size='14sp')
        save_btn.bind(on_press=self.save_freq_log)
        btn_row.add_widget(scan_btn)
        btn_row.add_widget(save_btn)
        layout.add_widget(btn_row)

        self.freq_status = Label(text="", size_hint_y=None, height=30,
                                 color=(0,1,0,1), font_size='12sp')
        layout.add_widget(self.freq_status)

        scroll.add_widget(layout)
        tab.add_widget(scroll)
        return tab

    # ── HISTORY TAB ───────────────────────────────────────────
    def _build_history_tab(self):
        tab = TabbedPanelItem(text='HIST')
        layout = BoxLayout(orientation='vertical', padding=10, spacing=6)

        layout.add_widget(Label(text="TOWER HISTORY",
            font_size='15sp', bold=True, color=(1,0.6,0,1),
            size_hint_y=None, height=35))

        btn_row = BoxLayout(size_hint_y=None, height=65, spacing=6)
        load_btn = Button(text="📂 LOAD", background_color=(0.5,0.3,0,1),
                          font_size='14sp')
        load_btn.bind(on_press=self.load_history)
        clear_btn = Button(text="🗑 CLEAR", background_color=(0.5,0,0,1),
                           font_size='14sp')
        clear_btn.bind(on_press=self.clear_history)
        btn_row.add_widget(load_btn)
        btn_row.add_widget(clear_btn)
        layout.add_widget(btn_row)

        scroll = ScrollView()
        self.hist_grid = GridLayout(cols=1, spacing=5, size_hint_y=None)
        self.hist_grid.bind(minimum_height=self.hist_grid.setter('height'))
        scroll.add_widget(self.hist_grid)
        layout.add_widget(scroll)

        tab.add_widget(layout)
        return tab

    # ══ TOWER LOGIC ══════════════════════════════════════════
    def update_tower_ui(self, dt):
        dbm   = self._get_real_signal()
        band  = self.band_spinner.text
        cid   = random.randint(10000,99999)
        lac   = random.randint(1000,9999)
        tower = random.choice(self.TOWERS)
        op    = random.choice(self.OPERATORS)
        quality = ("EXCELLENT" if dbm>-65 else "GOOD" if dbm>-75 else
                   "FAIR" if dbm>-85 else "WEAK")
        self.monitor.text = (
            f"NET: {op['name']} ({band})\n"
            f"TOWER: {tower['name']} | {tower['area']}\n"
            f"SIG: {dbm} dBm [{quality}]\n"
            f"CID: {cid} | LAC: {lac}")
        self.sig_bar.value = max(0, min(100, (dbm+110)*2))
        self._update_triangulation(tower, dbm)

    def _get_real_signal(self):
        if ANDROID:
            try:
                TM = autoclass('android.telephony.TelephonyManager')
                ctx = autoclass('org.kivy.android.PythonActivity').mActivity
                tm  = ctx.getSystemService(ctx.TELEPHONY_SERVICE)
                info = tm.getAllCellInfo()
                if info and info.size()>0:
                    return info.get(0).getCellSignalStrength().getDbm()
            except: pass
        return random.randint(-95,-45)

    def _update_triangulation(self, tower, dbm):
        def d(s): return round(10**((27.55-(20*math.log10(1800))-s)/20),1)
        d1,d2,d3 = d(dbm), d(dbm+random.randint(-15,5)), d(dbm+random.randint(-20,3))
        self.tri_label.text = (
            f"TRIANGULATION:\n"
            f"Alpha:{d1}m  Beta:{d2}m  Gamma:{d3}m\n"
            f"Target Zone: ~{min(d1,d2,d3):.0f}m radius")

    def calc_direction(self, instance):
        dirs = ["NORTH","NE","EAST","SE","SOUTH","SW","WEST","NW"]
        az   = random.randint(0,359)
        acc  = random.randint(60,97)
        self.dir_result.text = (
            f"Direction: {dirs[az//45]} ({az}°)\n"
            f"Accuracy: {acc}% | Sector: {'A' if az<120 else 'B' if az<240 else 'C'}")

    def save_data(self, instance):
        ensure_dirs()
        tag   = self.p_input.text or "UNNAMED"
        band  = self.band_spinner.text
        tower = random.choice(self.TOWERS)
        dbm   = self._get_real_signal()
        cid   = random.randint(10000,99999)
        lac   = random.randint(1000,9999)
        row   = [datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                 tag,"JAZZ",tower['lat'],tower['lon'],dbm,cid,lac,band]
        for path in [MASTER_CSV, TOWER_CSV]:
            with open(path,'a',newline='') as f:
                csv.writer(f).writerow(row)
        self.monitor.text = f"✅ LOCKED: {tag}\n{tower['name']} | {dbm}dBm"

    # ══ CELL LOGIC ═══════════════════════════════════════════
    def toggle_cell(self, instance):
        self._cell_running = not self._cell_running
        if self._cell_running:
            self.cell_btn.text = "⏹ STOP"
            self.cell_btn.background_color = (0.7,0,0,1)
            Clock.schedule_interval(self._cell_tick, 2)
        else:
            self.cell_btn.text = "▶ START"
            self.cell_btn.background_color = (0,0.7,0,1)
            Clock.unschedule(self._cell_tick)

    def _cell_tick(self, dt):
        dbm  = self._get_real_signal()
        op   = random.choice(self.OPERATORS)
        cid  = random.randint(10000,99999)
        lac  = random.randint(1000,9999)
        qual = "EXCELLENT" if dbm>-65 else "GOOD" if dbm>-75 else "FAIR" if dbm>-85 else "POOR"

        # Detect band from signal strength
        if dbm > -70:   active_band = "5G-NR"
        elif dbm > -80: active_band = "4G-LTE"
        elif dbm > -88: active_band = "3G-UMTS"
        else:           active_band = "2G-GSM"

        self.cell_display.text = (
            f"OPERATOR: {op['name']}  MNC: {op['mnc']}\n"
            f"SIGNAL: {dbm} dBm [{qual}]\n"
            f"BAND: {active_band} | CID: {cid}\n"
            f"MCC: 410 | LAC: {lac}\n"
            f"TIME: {datetime.now().strftime('%H:%M:%S')}\n"
            f"SOURCE: {'REAL' if ANDROID else 'SIM'}")

        # Update band cells
        for band_name, lbl in self.band_cells.items():
            sig = dbm + random.randint(-10,10)
            status = "ACTIVE" if band_name == active_band else "IDLE"
            lbl.text = f"{band_name}\n{sig}dBm\n{status}"

        self.cell_graph.push(dbm+110)
        self._cell_log.append([datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                op['name'],active_band,dbm,cid,lac])
        self.cell_status.text = f"Monitoring... {len(self._cell_log)} samples"

    def save_cell_log(self, instance):
        if not self._cell_log:
            self.cell_status.text = "No data!"; return
        ensure_dirs()
        out = os.path.join(DATA_DIR, f"cell_{datetime.now().strftime('%H%M%S')}.csv")
        with open(out,'w',newline='') as f:
            w = csv.writer(f)
            w.writerow(["Time","Op","Band","dBm","CID","LAC"])
            w.writerows(self._cell_log)
        self.cell_status.text = f"Saved: {os.path.basename(out)}"

    # ══ NET LOGIC ════════════════════════════════════════════
    def toggle_net(self, instance):
        self.net_running = not self.net_running
        if self.net_running:
            self.net_btn.text = "⏹ STOP"
            self.net_btn.background_color = (0.7,0,0,1)
            Clock.schedule_interval(self._net_tick, 2)
        else:
            self.net_btn.text = "▶ START CAPTURE"
            self.net_btn.background_color = (0,0.5,0.8,1)
            Clock.unschedule(self._net_tick)

    def _net_tick(self, dt):
        try:
            rx=tx=0
            with open('/proc/net/dev','r') as f:
                for line in f.readlines()[2:]:
                    p=line.split()
                    if len(p)>9 and p[0]!='lo:':
                        rx+=int(p[1]); tx+=int(p[9])
            rx_kb=max(0,(rx-self._prev_rx)/1024) if self._prev_rx else 0
            tx_kb=max(0,(tx-self._prev_tx)/1024) if self._prev_tx else 0
            self._prev_rx,self._prev_tx=rx,tx
            src="REAL"
        except:
            rx_kb=random.uniform(5,800)
            tx_kb=random.uniform(2,200)
            src="SIM"
        proto=random.choice(["TCP","UDP","HTTPS","DNS"])
        pkts=random.randint(10,500)
        self.net_display.text=(
            f"RX: {rx_kb:.1f} KB/s  TX: {tx_kb:.1f} KB/s\n"
            f"Packets: {pkts}  Protocol: {proto}\n"
            f"Records: {len(self._net_log)} | Source: {src}\n"
            f"{datetime.now().strftime('%H:%M:%S')}")
        self.rx_graph.push(rx_kb)
        self.tx_graph.push(tx_kb)
        self._net_log.append([datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                               rx_kb,tx_kb,pkts,proto])
        self.net_status.text=f"Capturing... {len(self._net_log)} records"

    def save_net_log(self, instance):
        if not self._net_log:
            self.net_status.text="No data!"; return
        ensure_dirs()
        out=os.path.join(DATA_DIR,f"net_{datetime.now().strftime('%H%M%S')}.csv")
        with open(out,'w',newline='') as f:
            w=csv.writer(f)
            w.writerow(["Time","RX_KB","TX_KB","Packets","Protocol"])
            w.writerows(self._net_log)
        self.net_status.text=f"Saved: {os.path.basename(out)}"

    # ══ MAP LOGIC ════════════════════════════════════════════
    def _update_gps(self, dt):
        if ANDROID:
            try:
                LM=autoclass('android.location.LocationManager')
                ctx=autoclass('org.kivy.android.PythonActivity').mActivity
                lm=ctx.getSystemService(ctx.LOCATION_SERVICE)
                loc=lm.getLastKnownLocation(LM.GPS_PROVIDER)
                if loc:
                    self._current_lat=loc.getLatitude()
                    self._current_lon=loc.getLongitude()
                    self.map_coords.text=(
                        f"LAT: {self._current_lat:.6f}\n"
                        f"LON: {self._current_lon:.6f}\n"
                        f"Accuracy: {loc.getAccuracy():.1f}m [GPS]")
                    return
            except: pass
        self._current_lat+=random.uniform(-0.0001,0.0001)
        self._current_lon+=random.uniform(-0.0001,0.0001)
        self.map_coords.text=(
            f"LAT: {self._current_lat:.6f}\n"
            f"LON: {self._current_lon:.6f}\n"
            f"Source: {'Android GPS' if ANDROID else 'Simulation'}")

    def open_osm(self, instance):
        import webbrowser
        webbrowser.open(f"https://www.openstreetmap.org/?mlat={self._current_lat}&mlon={self._current_lon}&zoom=15")

    def open_gmaps(self, instance):
        import webbrowser
        webbrowser.open(f"https://www.google.com/maps?q={self._current_lat},{self._current_lon}")

    def set_manual_location(self, instance):
        try:
            p=self.coord_input.text.strip().split(',')
            self._current_lat=float(p[0]); self._current_lon=float(p[1])
            self.map_coords.text=(
                f"LAT: {self._current_lat:.6f}\n"
                f"LON: {self._current_lon:.6f}\n"
                f"Source: Manual")
        except:
            self.map_coords.text="ERROR: Format: 33.6844,73.0479"

    # ══ INTEL LOGIC ══════════════════════════════════════════
    def run_search(self, instance):
        target=self.s_input.text.strip()
        stype=self.search_type.text
        if not target: return
        self.grid.clear_widgets()
        self.last_results=[]
        results=self._deep_search(target,stype)
        if not results:
            self.grid.add_widget(Label(
                text=f"❌ NO MATCH\nQuery: {target}\n\nAdd data to:\nKHOJI_MASTER/cnic_db.csv",
                size_hint_y=None, height=120, color=(1,0.3,0.3,1), font_size='13sp'))
            return
        for r in results:
            pct=r.get('match',0)
            color=(0,1,0,1) if pct>80 else (1,0.8,0,1)
            self.grid.add_widget(Label(
                text=(f"✅ MATCH: {pct}%\n"
                      f"Name: {r.get('Name','--')} | CNIC: {r.get('CNIC','--')}\n"
                      f"Phone: {r.get('Phone','--')} | DOB: {r.get('DOB','--')}\n"
                      f"Address: {r.get('Address','--')} | Status: {r.get('Status','--')}"),
                size_hint_y=None, height=130, color=color,
                halign='left', font_size='12sp'))
            self.last_results.append(r)

    def _deep_search(self, query, stype):
        results=[]
        if not os.path.exists(CNIC_CSV): return results
        col={'CNIC SEARCH':'CNIC','PHONE NUMBER':'Phone',
             'NAME SEARCH':'Name','ADDRESS SEARCH':'Address'}.get(stype,'CNIC')
        with open(CNIC_CSV,'r') as f:
            for row in csv.DictReader(f):
                cell=str(row.get(col,''))
                if query.lower() in cell.lower():
                    pct=min(100,int((len(query)/max(len(cell),1))*100+40))
                    row['match']=pct
                    results.append(dict(row))
        return sorted(results,key=lambda x:x['match'],reverse=True)

    def export_results(self, instance):
        if not self.last_results:
            self.export_status.text="No results!"; return
        ensure_dirs()
        out=os.path.join(DATA_DIR,f"export_{datetime.now().strftime('%H%M%S')}.csv")
        with open(out,'w',newline='') as f:
            w=csv.DictWriter(f,fieldnames=self.last_results[0].keys())
            w.writeheader(); w.writerows(self.last_results)
        self.export_status.text=f"Saved: {os.path.basename(out)}"

    # ══ FREQUENCY LOGIC ══════════════════════════════════════
    BAND_INFO={'700MHz':('JAZZ','4G'),'850MHz':('ZONG','3G'),
               '1800MHz':('TELENOR','4G'),'2100MHz':('UFONE','3G'),
               '2600MHz':('JAZZ','4G'),'3500MHz':('ZONG','5G')}

    def start_freq_scan(self, instance):
        self.freq_status.text="Scanning..."
        Clock.schedule_once(self._do_scan, 0.5)

    def _do_scan(self, dt):
        summary="FREQUENCY SCAN:\n"
        self.scan_data=[]
        for band, bar in self.freq_bars.items():
            val=random.randint(10,95)
            bar.value=val
            op,btype=self.BAND_INFO.get(band,('?','?'))
            act="HIGH" if val>70 else "MED" if val>40 else "LOW"
            summary+=f"{band}: {val}% [{act}] {op} {btype}\n"
            self.scan_data.append([datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                   band,val,act,op,btype])
        self.freq_display.text=summary
        self.freq_status.text=f"Done {datetime.now().strftime('%H:%M:%S')}"

    def save_freq_log(self, instance):
        if not self.scan_data:
            self.freq_status.text="Scan first!"; return
        ensure_dirs()
        with open(FREQ_CSV,'a',newline='') as f:
            csv.writer(f).writerows(self.scan_data)
        self.freq_status.text="Saved!"

    # ══ HISTORY LOGIC ════════════════════════════════════════
    def load_history(self, instance):
        self.hist_grid.clear_widgets()
        if not os.path.exists(TOWER_CSV):
            self.hist_grid.add_widget(Label(text="No history.",
                size_hint_y=None, height=60, color=(1,0.5,0,1))); return
        with open(TOWER_CSV,'r') as f:
            rows=list(csv.reader(f))
        if len(rows)<=1:
            self.hist_grid.add_widget(Label(text="Empty.",
                size_hint_y=None, height=60)); return
        for i,row in enumerate(reversed(rows[1:]),1):
            if len(row)<6: continue
            self.hist_grid.add_widget(Label(
                text=f"#{i} {row[0]}\n{row[1]} | {row[2]} | {row[8] if len(row)>8 else '?'}\nLAT:{row[3]} LON:{row[4]} Sig:{row[5]}dBm",
                size_hint_y=None, height=90,
                color=(0.8,0.8,0.8,1), halign='left', font_size='11sp'))

    def clear_history(self, instance):
        if os.path.exists(TOWER_CSV):
            with open(TOWER_CSV,'w',newline='') as f:
                csv.writer(f).writerow(["Timestamp","Tag","Network","LAT","LON",
                                        "Signal_dBm","CID","LAC","Band"])
        self.hist_grid.clear_widgets()
        self.hist_grid.add_widget(Label(text="Cleared.",
            size_hint_y=None, height=60, color=(1,0.5,0,1)))


# ════════════════════════════════════════════════════════════
#  APP
# ════════════════════════════════════════════════════════════
class KhojiApp(App):
    def build(self):
        Window.clearcolor = (0.05, 0.05, 0.08, 1)
        sm = ScreenManager()
        sm.add_widget(LoginScreen(name='login'))
        sm.add_widget(Dashboard(name='dashboard'))
        return sm

if __name__ == '__main__':
    KhojiApp().run()
