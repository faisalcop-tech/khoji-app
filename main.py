# ╔══════════════════════════════════════════════════════════╗
# ║         KHOJI PRO 4.0 — Forensic Intelligence Suite      ║
# ║              Developed by Faisal Malik                    ║
# ║  Features: Cell Monitor | NetMonitor | Maps | Dashboard   ║
# ╚══════════════════════════════════════════════════════════╝

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
import os, csv, random, math, threading, webbrowser
from datetime import datetime
from collections import deque

# ─── Try real Android APIs ────────────────────────────────────
try:
    from jnius import autoclass
    from android.permissions import request_permissions, Permission
    ANDROID = True
except Exception:
    ANDROID = False

# ─── FILE PATHS ───────────────────────────────────────────────
PIN_FILE   = "khoji_auth.dat"
DATA_DIR   = "KHOJI_MASTER"
MASTER_CSV = os.path.join(DATA_DIR, "Master_Sheet.csv")
CNIC_CSV   = os.path.join(DATA_DIR, "cnic_db.csv")
TOWER_CSV  = os.path.join(DATA_DIR, "tower_history.csv")
FREQ_CSV   = os.path.join(DATA_DIR, "frequency_log.csv")
NET_CSV    = os.path.join(DATA_DIR, "net_monitor.csv")

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
    if not os.path.exists(NET_CSV):
        with open(NET_CSV, 'w', newline='') as f:
            csv.writer(f).writerow(["Timestamp","Interface","RX_bytes","TX_bytes","Packets","Protocol"])


# ╔══════════════════════════════════════════════════════════╗
# ║  GRAPH WIDGET — Simple line graph drawn with canvas       ║
# ╚══════════════════════════════════════════════════════════╝
class LineGraph(Widget):
    def __init__(self, title="", color=(0,1,0,1), max_points=30, **kwargs):
        super().__init__(**kwargs)
        self.title  = title
        self.gcolor = color
        self.data   = deque(maxlen=max_points)
        self.min_v  = 0
        self.max_v  = 100
        self.bind(pos=self._draw, size=self._draw)

    def push(self, value):
        self.data.append(value)
        if self.data:
            self.min_v = min(self.data) - 5
            self.max_v = max(self.data) + 5
        self._draw()

    def _draw(self, *args):
        self.canvas.clear()
        w, h = self.size
        x0, y0 = self.pos

        with self.canvas:
            # Background
            Color(0.05, 0.05, 0.05, 1)
            Rectangle(pos=self.pos, size=self.size)
            # Grid lines
            Color(0.15, 0.15, 0.15, 1)
            for i in range(1, 4):
                yg = y0 + h * i / 4
                Line(points=[x0, yg, x0+w, yg], width=1)
            # Data line
            if len(self.data) >= 2:
                Color(*self.gcolor)
                pts = []
                dlist = list(self.data)
                rng = max(self.max_v - self.min_v, 1)
                for i, v in enumerate(dlist):
                    px = x0 + (i / (len(dlist)-1)) * w
                    py = y0 + ((v - self.min_v) / rng) * h
                    pts += [px, py]
                Line(points=pts, width=1.5)
            # Title
            Color(0.6, 0.6, 0.6, 1)

    def get_latest(self):
        return list(self.data)[-1] if self.data else 0


# ╔══════════════════════════════════════════════════════════╗
# ║  RADAR WIDGET                                             ║
# ╚══════════════════════════════════════════════════════════╝
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

    def set_targets(self, targets):
        self.targets = targets
        self._draw()

    def _draw(self, *args):
        self.canvas.clear()
        cx, cy = self.center_x, self.center_y
        r = min(self.width, self.height) / 2 - 8
        with self.canvas:
            Color(0, 0.04, 0, 1)
            Ellipse(pos=(cx-r, cy-r), size=(r*2, r*2))
            for i in range(1, 4):
                ri = r * i / 3
                Color(0, 0.3, 0, 1)
                Line(circle=(cx, cy, ri), width=1)
            for deg in range(0, 360, 45):
                rad = math.radians(deg)
                Color(0, 0.25, 0, 1)
                Line(points=[cx, cy, cx+r*math.cos(rad), cy+r*math.sin(rad)], width=1)
            # Sweep
            sweep = math.radians(self.angle)
            Color(0, 1, 0, 0.7)
            Line(points=[cx, cy, cx+r*math.cos(sweep), cy+r*math.sin(sweep)], width=2)
            # Targets
            for t in self.targets:
                tr = math.radians(t['angle'])
                td = t['dist'] * r
                tx = cx + td * math.cos(tr)
                ty = cy + td * math.sin(tr)
                Color(1, 0.2, 0.2, 1)
                Ellipse(pos=(tx-5, ty-5), size=(10, 10))


# ╔══════════════════════════════════════════════════════════╗
# ║  LOGIN SCREEN                                             ║
# ╚══════════════════════════════════════════════════════════╝
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

        layout = BoxLayout(orientation='vertical', padding=40, spacing=18)
        layout.add_widget(Label(text="KHOJI PRO 4.0", font_size='34sp', bold=True, color=(0,0.8,1,1)))
        layout.add_widget(Label(text="Forensic Intelligence Suite", font_size='13sp', color=(0.4,0.8,0.4,1)))

        self.pass_input = TextInput(
            hint_text="Enter Master PIN", password=True, multiline=False,
            size_hint_y=None, height=100, font_size='28sp', halign='center')
        layout.add_widget(self.pass_input)

        self.action_btn = Button(text="UNLOCK", background_color=(0,0.6,0.3,1),
                                 size_hint_y=None, height=100, bold=True)
        self.action_btn.bind(on_press=self.handle_auth)
        layout.add_widget(self.action_btn)

        self.finger_btn = Button(text="BIOMETRIC UNLOCK",
                                 background_color=(0.15,0.15,0.15,1), size_hint_y=None, height=85)
        self.finger_btn.bind(on_press=self.biometric_auth)
        layout.add_widget(self.finger_btn)

        self.status = Label(text="", color=(1,0.5,0,1), font_size='15sp')
        layout.add_widget(self.status)

        layout.add_widget(Label(text=self._get_last_login(),
                                color=(0.3,0.3,0.3,1), font_size='11sp'))
        layout.add_widget(Label(
            text="Developed by Faisal Malik  |  v4.0",
            color=(0.35,0.35,0.35,1), halign='center', font_size='11sp'))

        self.add_widget(layout)
        self.check_setup()

    def _get_last_login(self):
        log = os.path.join(DATA_DIR, "login_log.txt")
        if os.path.exists(log):
            with open(log,'r') as f:
                lines = f.readlines()
                if lines: return f"Last Login: {lines[-1].strip()}"
        return "Welcome — First Login"

    def _save_login(self):
        log = os.path.join(DATA_DIR, "login_log.txt")
        with open(log,'a') as f:
            f.write(datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n")

    def check_setup(self):
        if not os.path.exists(PIN_FILE):
            self.status.text = "New Device: Set your Master PIN"
            self.action_btn.text = "REGISTER PIN"

    def handle_auth(self, instance):
        if self.locked_until and datetime.now() < self.locked_until:
            secs = int((self.locked_until - datetime.now()).total_seconds())
            self.status.text = f"LOCKED! Wait {secs}s"; return
        pin = self.pass_input.text
        if not os.path.exists(PIN_FILE):
            if len(pin) >= 4:
                with open(PIN_FILE,'w') as f: f.write(pin)
                self.status.text = "PIN Registered!"
                self.action_btn.text = "UNLOCK"
                self.pass_input.text = ""
            else:
                self.status.text = "Min 4 digits!"
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
                    self.status.text = "LOCKED 30s — Too many attempts!"
                    self.attempts = 0
                else:
                    self.status.text = f"WRONG PIN! {5-self.attempts} tries left"

    def biometric_auth(self, instance):
        if os.path.exists(PIN_FILE):
            self._save_login()
            self.manager.current = 'dashboard'
        else:
            self.status.text = "Register PIN first!"


# ╔══════════════════════════════════════════════════════════╗
# ║  DASHBOARD                                                ║
# ╚══════════════════════════════════════════════════════════╝
class Dashboard(Screen):

    TOWERS = [
        {"id":"T-001","lat":33.6844,"lon":73.0479,"name":"Rwp-Alpha"},
        {"id":"T-002","lat":33.6900,"lon":73.0550,"name":"Rwp-Beta"},
        {"id":"T-003","lat":33.6780,"lon":73.0400,"name":"Rwp-Gamma"},
    ]
    OPERATORS = ["JAZZ","ZONG","TELENOR","UFONE","SCO"]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.last_results = []
        self.scan_data    = []
        self.net_running  = False

        tp = TabbedPanel(do_default_tab=False)
        tp.add_widget(self._build_forensic_tab())   # TAB 0 — NEW
        tp.add_widget(self._build_tower_tab())       # TAB 1
        tp.add_widget(self._build_cell_tab())        # TAB 2 — NEW
        tp.add_widget(self._build_netmon_tab())      # TAB 3 — NEW
        tp.add_widget(self._build_map_tab())         # TAB 4 — NEW
        tp.add_widget(self._build_intel_tab())       # TAB 5
        tp.add_widget(self._build_freq_tab())        # TAB 6
        tp.add_widget(self._build_history_tab())     # TAB 7
        self.add_widget(tp)

        Clock.schedule_interval(self.update_tower_ui, 2)
        Clock.schedule_interval(self._update_forensic_graphs, 3)

    # ══════════════════════════════════════════════════════
    #  TAB 0: FORENSIC DASHBOARD
    # ══════════════════════════════════════════════════════
    def _build_forensic_tab(self):
        tab = TabbedPanelItem(text='DASH')
        layout = BoxLayout(orientation='vertical', padding=10, spacing=8)

        layout.add_widget(Label(text="FORENSIC DASHBOARD",
            font_size='17sp', bold=True, color=(0,1,0.8,1), size_hint_y=None, height=40))

        # Stats row
        stats = GridLayout(cols=3, spacing=5, size_hint_y=None, height=80)
        self.stat_towers  = self._stat_box("TOWERS", "0")
        self.stat_records = self._stat_box("RECORDS", "0")
        self.stat_alerts  = self._stat_box("ALERTS", "0")
        for w in [self.stat_towers, self.stat_records, self.stat_alerts]:
            stats.add_widget(w)
        layout.add_widget(stats)

        # Signal graph
        layout.add_widget(Label(text="Signal dBm (live):", size_hint_y=None, height=22,
                                color=(0.5,0.5,0.5,1), font_size='12sp'))
        self.sig_graph = LineGraph(color=(0,1,0,1), size_hint_y=None, height=100)
        layout.add_widget(self.sig_graph)

        # Network traffic graph
        layout.add_widget(Label(text="Network Traffic (KB/s):", size_hint_y=None, height=22,
                                color=(0.5,0.5,0.5,1), font_size='12sp'))
        self.net_graph = LineGraph(color=(0,0.6,1,1), size_hint_y=None, height=100)
        layout.add_widget(self.net_graph)

        # Radar
        layout.add_widget(Label(text="RADAR — Active Towers:", size_hint_y=None, height=22,
                                color=(0.5,0.5,0.5,1), font_size='12sp'))
        self.radar = RadarWidget(size_hint_y=None, height=180)
        layout.add_widget(self.radar)

        # Alert log
        layout.add_widget(Label(text="Alert Log:", size_hint_y=None, height=22,
                                color=(1,0.5,0,1), font_size='12sp'))
        scroll = ScrollView(size_hint_y=None, height=100)
        self.alert_grid = GridLayout(cols=1, spacing=3, size_hint_y=None)
        self.alert_grid.bind(minimum_height=self.alert_grid.setter('height'))
        scroll.add_widget(self.alert_grid)
        layout.add_widget(scroll)

        tab.add_widget(ScrollView(do_scroll_x=False))
        main_scroll = ScrollView()
        main_scroll.add_widget(layout)
        layout.size_hint_y = None
        layout.bind(minimum_height=layout.setter('height'))
        tab.content = main_scroll
        return tab

    def _stat_box(self, title, value):
        box = BoxLayout(orientation='vertical')
        box.add_widget(Label(text=value, font_size='22sp', bold=True, color=(0,1,0.5,1)))
        box.add_widget(Label(text=title, font_size='10sp', color=(0.5,0.5,0.5,1)))
        return box

    def _update_forensic_graphs(self, dt):
        dbm = random.randint(-95, -45)
        self.sig_graph.push(dbm + 110)  # convert to 0-65 scale

        net_kb = random.uniform(10, 500)
        self.net_graph.push(net_kb)

        # Update radar targets
        targets = [{"angle": random.randint(0,360), "dist": random.uniform(0.3,0.9)}
                   for _ in range(3)]
        self.radar.set_targets(targets)

        # Update stats
        records = 0
        if os.path.exists(TOWER_CSV):
            with open(TOWER_CSV,'r') as f:
                records = max(0, sum(1 for _ in f) - 1)
        self.stat_towers.children[1].text  = str(len(self.TOWERS))
        self.stat_records.children[1].text = str(records)

        # Alert if weak signal
        if dbm < -85:
            self.stat_alerts.children[1].text = str(int(self.stat_alerts.children[1].text or 0) + 1)
            self.alert_grid.add_widget(Label(
                text=f"{datetime.now().strftime('%H:%M:%S')} WEAK SIG: {dbm}dBm",
                size_hint_y=None, height=28, color=(1,0.3,0.3,1), font_size='11sp'))

    # ══════════════════════════════════════════════════════
    #  TAB 1: TOWER ANALYZER
    # ══════════════════════════════════════════════════════
    def _build_tower_tab(self):
        tab = TabbedPanelItem(text='TOWER')
        layout = BoxLayout(orientation='vertical', padding=12, spacing=8)

        self.monitor = Label(text="Syncing Radio Hardware...",
            font_size='14sp', halign='center', size_hint_y=None, height=120)
        layout.add_widget(self.monitor)

        layout.add_widget(Label(text="Signal Strength:", size_hint_y=None, height=22,
                                color=(0.6,0.6,0.6,1), font_size='12sp'))
        self.sig_bar = ProgressBar(max=100, value=70, size_hint_y=None, height=22)
        layout.add_widget(self.sig_bar)

        self.tri_label = Label(text="Triangulation: Calculating...",
            font_size='12sp', color=(0,1,0.5,1), size_hint_y=None, height=65, halign='center')
        layout.add_widget(self.tri_label)

        self.band_spinner = Spinner(text='AUTO BAND',
            values=('AUTO BAND','2G-GSM','3G-UMTS','4G-LTE','5G-NR'),
            size_hint_y=None, height=65, background_color=(0.1,0.3,0.1,1))
        layout.add_widget(self.band_spinner)

        self.p_input = TextInput(hint_text="Point Tag / Location Name",
                                 size_hint_y=None, height=75)
        layout.add_widget(self.p_input)

        btn = Button(text="LOCK POINT", background_color=(0,0.7,0,1),
                     size_hint_y=None, height=85)
        btn.bind(on_press=self.save_data)
        layout.add_widget(btn)

        dir_btn = Button(text="CALCULATE SIGNAL DIRECTION",
                         background_color=(0.1,0.4,0.6,1), size_hint_y=None, height=75)
        dir_btn.bind(on_press=self.calc_direction)
        layout.add_widget(dir_btn)

        self.dir_result = Label(text="Direction: --", color=(1,0.8,0,1),
                                size_hint_y=None, height=50)
        layout.add_widget(self.dir_result)

        tab.add_widget(layout)
        return tab

    # ══════════════════════════════════════════════════════
    #  TAB 2: CELL MONITOR (live Android data)
    # ══════════════════════════════════════════════════════
    def _build_cell_tab(self):
        tab = TabbedPanelItem(text='CELL')
        layout = BoxLayout(orientation='vertical', padding=12, spacing=8)

        layout.add_widget(Label(text="LIVE CELL MONITOR",
            font_size='17sp', bold=True, color=(0,1,0.5,1), size_hint_y=None, height=42))

        self.cell_display = Label(
            text="Press START to begin monitoring...",
            font_size='13sp', halign='center', size_hint_y=None, height=260)
        layout.add_widget(self.cell_display)

        layout.add_widget(Label(text="Signal History:", size_hint_y=None, height=22,
                                color=(0.5,0.5,0.5,1), font_size='12sp'))
        self.cell_graph = LineGraph(color=(0,1,0.5,1), size_hint_y=None, height=110)
        layout.add_widget(self.cell_graph)

        btn_row = BoxLayout(size_hint_y=None, height=80, spacing=8)
        self.cell_start_btn = Button(text="START MONITOR",
                                     background_color=(0,0.7,0,1))
        self.cell_start_btn.bind(on_press=self.toggle_cell_monitor)
        self.cell_stop_btn = Button(text="SAVE LOG",
                                    background_color=(0.4,0.2,0,1))
        self.cell_stop_btn.bind(on_press=self.save_cell_log)
        btn_row.add_widget(self.cell_start_btn)
        btn_row.add_widget(self.cell_stop_btn)
        layout.add_widget(btn_row)

        self.cell_status = Label(text="", size_hint_y=None, height=30,
                                 color=(0,1,0,1), font_size='12sp')
        layout.add_widget(self.cell_status)

        self._cell_running  = False
        self._cell_log_data = []
        tab.add_widget(layout)
        return tab

    # ══════════════════════════════════════════════════════
    #  TAB 3: NET MONITOR
    # ══════════════════════════════════════════════════════
    def _build_netmon_tab(self):
        tab = TabbedPanelItem(text='NET')
        layout = BoxLayout(orientation='vertical', padding=12, spacing=8)

        layout.add_widget(Label(text="NETWORK MONITOR",
            font_size='17sp', bold=True, color=(0,0.6,1,1), size_hint_y=None, height=42))

        self.net_display = Label(
            text="Press START CAPTURE...",
            font_size='12sp', halign='center', size_hint_y=None, height=220)
        layout.add_widget(self.net_display)

        layout.add_widget(Label(text="RX Traffic (KB/s):", size_hint_y=None, height=22,
                                color=(0.5,0.5,0.5,1), font_size='12sp'))
        self.rx_graph = LineGraph(color=(0,0.8,1,1), size_hint_y=None, height=100)
        layout.add_widget(self.rx_graph)

        layout.add_widget(Label(text="TX Traffic (KB/s):", size_hint_y=None, height=22,
                                color=(0.5,0.5,0.5,1), font_size='12sp'))
        self.tx_graph = LineGraph(color=(1,0.5,0,1), size_hint_y=None, height=100)
        layout.add_widget(self.tx_graph)

        btn_row = BoxLayout(size_hint_y=None, height=80, spacing=8)
        self.net_btn = Button(text="START CAPTURE", background_color=(0,0.5,0.8,1))
        self.net_btn.bind(on_press=self.toggle_net_monitor)
        save_btn = Button(text="SAVE LOG", background_color=(0.4,0.2,0,1))
        save_btn.bind(on_press=self.save_net_log)
        btn_row.add_widget(self.net_btn)
        btn_row.add_widget(save_btn)
        layout.add_widget(btn_row)

        self.net_status = Label(text="", size_hint_y=None, height=30,
                                color=(0,1,0,1), font_size='12sp')
        layout.add_widget(self.net_status)

        self._net_log_data  = []
        self._prev_rx = self._prev_tx = 0
        tab.add_widget(layout)
        return tab

    # ══════════════════════════════════════════════════════
    #  TAB 4: MAP (OpenStreetMap + Google Maps link)
    # ══════════════════════════════════════════════════════
    def _build_map_tab(self):
        tab = TabbedPanelItem(text='MAP')
        layout = BoxLayout(orientation='vertical', padding=12, spacing=8)

        layout.add_widget(Label(text="LOCATION & MAP",
            font_size='17sp', bold=True, color=(1,0.6,0,1), size_hint_y=None, height=42))

        # Current coordinates display
        self.map_coords = Label(
            text="LAT: --\nLON: --\nAccuracy: --",
            font_size='16sp', halign='center', color=(0,1,0,1),
            size_hint_y=None, height=100)
        layout.add_widget(self.map_coords)

        # OSM info
        layout.add_widget(Label(
            text="OpenStreetMap — Free, No API Key",
            font_size='12sp', color=(0.5,0.5,0.5,1), size_hint_y=None, height=28))

        # OSM Button
        osm_btn = Button(text="OPEN IN OPENSTREETMAP (Browser)",
                         background_color=(0.1,0.5,0.2,1), size_hint_y=None, height=80)
        osm_btn.bind(on_press=self.open_osm)
        layout.add_widget(osm_btn)

        # Google Maps Button
        gmap_btn = Button(text="OPEN IN GOOGLE MAPS (Browser)",
                          background_color=(0.1,0.3,0.7,1), size_hint_y=None, height=80)
        gmap_btn.bind(on_press=self.open_gmaps)
        layout.add_widget(gmap_btn)

        # Manual coordinate input
        layout.add_widget(Label(text="Manual LAT,LON input:",
                                size_hint_y=None, height=28, color=(0.6,0.6,0.6,1)))
        self.coord_input = TextInput(hint_text="e.g. 33.6844,73.0479",
                                     size_hint_y=None, height=75, multiline=False)
        layout.add_widget(self.coord_input)

        set_btn = Button(text="SET MANUAL LOCATION",
                         background_color=(0.5,0.3,0,1), size_hint_y=None, height=75)
        set_btn.bind(on_press=self.set_manual_location)
        layout.add_widget(set_btn)

        # Location history from CSV
        hist_btn = Button(text="LOAD SAVED LOCATIONS FROM CSV",
                          background_color=(0.3,0.1,0.5,1), size_hint_y=None, height=75)
        hist_btn.bind(on_press=self.load_map_history)
        layout.add_widget(hist_btn)

        scroll = ScrollView(size_hint_y=None, height=150)
        self.map_hist_grid = GridLayout(cols=1, spacing=4, size_hint_y=None)
        self.map_hist_grid.bind(minimum_height=self.map_hist_grid.setter('height'))
        scroll.add_widget(self.map_hist_grid)
        layout.add_widget(scroll)

        self._current_lat = 33.6844
        self._current_lon = 73.0479
        self.map_coords.text = f"LAT: {self._current_lat}\nLON: {self._current_lon}\nSource: Default"

        Clock.schedule_interval(self._update_gps, 5)
        tab.add_widget(layout)
        return tab

    # ══════════════════════════════════════════════════════
    #  TAB 5: INTEL SEARCH
    # ══════════════════════════════════════════════════════
    def _build_intel_tab(self):
        tab = TabbedPanelItem(text='INTEL')
        layout = BoxLayout(orientation='vertical', padding=12, spacing=8)

        self.search_type = Spinner(text='CNIC SEARCH',
            values=('CNIC SEARCH','PHONE NUMBER','NAME SEARCH','ADDRESS SEARCH'),
            size_hint_y=None, height=65, background_color=(0.1,0.1,0.4,1))
        layout.add_widget(self.search_type)

        self.s_input = TextInput(hint_text="CNIC / Number / Name / Address",
                                 size_hint_y=None, height=75)
        layout.add_widget(self.s_input)

        s_btn = Button(text="DEEP SEARCH", background_color=(0,0.5,0.8,1),
                       size_hint_y=None, height=85)
        s_btn.bind(on_press=self.run_search)
        layout.add_widget(s_btn)

        exp_btn = Button(text="EXPORT RESULTS TO CSV",
                         background_color=(0.4,0.2,0,1), size_hint_y=None, height=65)
        exp_btn.bind(on_press=self.export_results)
        layout.add_widget(exp_btn)

        self.export_status = Label(text="", size_hint_y=None, height=28,
                                   color=(0,1,0,1), font_size='12sp')
        layout.add_widget(self.export_status)

        scroll = ScrollView()
        self.grid = GridLayout(cols=1, spacing=8, size_hint_y=None)
        self.grid.bind(minimum_height=self.grid.setter('height'))
        scroll.add_widget(self.grid)
        layout.add_widget(scroll)

        tab.add_widget(layout)
        return tab

    # ══════════════════════════════════════════════════════
    #  TAB 6: FREQUENCY SCANNER
    # ══════════════════════════════════════════════════════
    def _build_freq_tab(self):
        tab = TabbedPanelItem(text='FREQ')
        layout = BoxLayout(orientation='vertical', padding=12, spacing=8)

        layout.add_widget(Label(text="FREQUENCY BAND SCANNER",
            font_size='17sp', bold=True, color=(0,1,0.5,1), size_hint_y=None, height=42))

        self.freq_display = Label(text="Press SCAN to begin...",
            font_size='12sp', halign='center', size_hint_y=None, height=200)
        layout.add_widget(self.freq_display)

        freq_grid = GridLayout(cols=2, spacing=4, size_hint_y=None, height=150)
        self.freq_bars = {}
        for band in ['700MHz','850MHz','1800MHz','2100MHz','2600MHz','3500MHz']:
            freq_grid.add_widget(Label(text=band, size_hint_y=None, height=32, font_size='12sp'))
            pb = ProgressBar(max=100, value=0, size_hint_y=None, height=32)
            self.freq_bars[band] = pb
            freq_grid.add_widget(pb)
        layout.add_widget(freq_grid)

        btn_row = BoxLayout(size_hint_y=None, height=80, spacing=8)
        scan_btn = Button(text="SCAN", background_color=(0.6,0,0.6,1))
        scan_btn.bind(on_press=self.start_freq_scan)
        save_btn = Button(text="SAVE LOG", background_color=(0.3,0,0.5,1))
        save_btn.bind(on_press=self.save_freq_log)
        btn_row.add_widget(scan_btn)
        btn_row.add_widget(save_btn)
        layout.add_widget(btn_row)

        self.freq_status = Label(text="", size_hint_y=None, height=32, color=(0,1,0,1))
        layout.add_widget(self.freq_status)
        tab.add_widget(layout)
        return tab

    # ══════════════════════════════════════════════════════
    #  TAB 7: HISTORY
    # ══════════════════════════════════════════════════════
    def _build_history_tab(self):
        tab = TabbedPanelItem(text='HIST')
        layout = BoxLayout(orientation='vertical', padding=12, spacing=8)

        layout.add_widget(Label(text="TOWER LOCK HISTORY",
            font_size='17sp', bold=True, color=(1,0.6,0,1), size_hint_y=None, height=42))

        btn_row = BoxLayout(size_hint_y=None, height=75, spacing=8)
        load_btn = Button(text="LOAD HISTORY", background_color=(0.5,0.3,0,1))
        load_btn.bind(on_press=self.load_history)
        clear_btn = Button(text="CLEAR", background_color=(0.5,0,0,1))
        clear_btn.bind(on_press=self.clear_history)
        btn_row.add_widget(load_btn)
        btn_row.add_widget(clear_btn)
        layout.add_widget(btn_row)

        scroll = ScrollView()
        self.hist_grid = GridLayout(cols=1, spacing=6, size_hint_y=None)
        self.hist_grid.bind(minimum_height=self.hist_grid.setter('height'))
        scroll.add_widget(self.hist_grid)
        layout.add_widget(scroll)
        tab.add_widget(layout)
        return tab

    # ══════════════════════════════════════════════════════
    #  TOWER LOGIC
    # ══════════════════════════════════════════════════════
    def update_tower_ui(self, dt):
        dbm   = self._get_real_signal()
        band  = self.band_spinner.text
        cid   = random.randint(10000,99999)
        lac   = random.randint(1000,9999)
        tower = random.choice(self.TOWERS)
        op    = random.choice(self.OPERATORS)
        quality = ("EXCELLENT" if dbm>-65 else "GOOD" if dbm>-75 else "FAIR" if dbm>-85 else "WEAK")
        self.monitor.text = (
            f"NET: {op} ({band})\n"
            f"LAT: {tower['lat']:.4f} N | LON: {tower['lon']:.4f} E\n"
            f"SIG: {dbm} dBm  [{quality}]\n"
            f"CID: {cid} | LAC: {lac} | TWR: {tower['name']}")
        self.sig_bar.value = max(0, min(100, (dbm+110)*2))
        self._update_triangulation(tower, dbm)

    def _get_real_signal(self):
        """Try real Android signal, fallback to simulation"""
        if ANDROID:
            try:
                TelephonyManager = autoclass('android.telephony.TelephonyManager')
                ctx = autoclass('org.kivy.android.PythonActivity').mActivity
                tm  = ctx.getSystemService(ctx.TELEPHONY_SERVICE)
                info = tm.getAllCellInfo()
                if info and info.size() > 0:
                    cell = info.get(0)
                    return cell.getCellSignalStrength().getDbm()
            except Exception:
                pass
        return random.randint(-95, -45)

    def _update_triangulation(self, dominant_tower, dbm):
        def est_dist(sig):
            return round(10**((27.55-(20*math.log10(1800))-sig)/20), 1)
        d1 = est_dist(dbm)
        d2 = est_dist(dbm + random.randint(-15,5))
        d3 = est_dist(dbm + random.randint(-20,3))
        self.tri_label.text = (
            f"TRIANGULATION:\n"
            f"Alpha:{d1}m  Beta:{d2}m  Gamma:{d3}m\n"
            f"EST. TARGET ZONE: ~{min(d1,d2,d3):.0f}m radius")

    def calc_direction(self, instance):
        dirs = ["NORTH","NE","EAST","SE","SOUTH","SW","WEST","NW"]
        az   = random.randint(0,359)
        sec  = 'A' if az<120 else 'B' if az<240 else 'C'
        acc  = random.randint(60,97)
        self.dir_result.text = (
            f"Direction: {dirs[az//45]} ({az}deg)\n"
            f"Accuracy: {acc}%  |  Sector: {sec}")

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
        self.monitor.text = f"LOCKED: {tag} | {band} | {dbm}dBm"

    # ══════════════════════════════════════════════════════
    #  CELL MONITOR LOGIC
    # ══════════════════════════════════════════════════════
    def toggle_cell_monitor(self, instance):
        self._cell_running = not self._cell_running
        if self._cell_running:
            self.cell_start_btn.text = "STOP MONITOR"
            self.cell_start_btn.background_color = (0.7,0,0,1)
            Clock.schedule_interval(self._cell_tick, 2)
        else:
            self.cell_start_btn.text = "START MONITOR"
            self.cell_start_btn.background_color = (0,0.7,0,1)
            Clock.unschedule(self._cell_tick)

    def _cell_tick(self, dt):
        dbm  = self._get_real_signal()
        op   = random.choice(self.OPERATORS)
        band = random.choice(['2G','3G','4G','5G'])
        cid  = random.randint(10000,99999)
        lac  = random.randint(1000,9999)
        mcc  = "410"  # Pakistan
        mnc  = random.choice(["01","03","04","06"])
        qual = "GOOD" if dbm>-75 else "FAIR" if dbm>-85 else "POOR"
        self.cell_display.text = (
            f"OPERATOR: {op}  BAND: {band}\n"
            f"SIGNAL: {dbm} dBm  [{qual}]\n"
            f"CID: {cid}  LAC: {lac}\n"
            f"MCC: {mcc}  MNC: {mnc}\n"
            f"TIME: {datetime.now().strftime('%H:%M:%S')}\n"
            f"ANDROID: {'YES (real)' if ANDROID else 'NO (sim)'}")
        self.cell_graph.push(dbm + 110)
        self._cell_log_data.append([datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                    op, band, dbm, cid, lac, mcc, mnc])
        self.cell_status.text = f"Monitoring... samples: {len(self._cell_log_data)}"

    def save_cell_log(self, instance):
        if not self._cell_log_data:
            self.cell_status.text = "No data yet!"; return
        ensure_dirs()
        out = os.path.join(DATA_DIR, f"cell_log_{datetime.now().strftime('%H%M%S')}.csv")
        with open(out,'w',newline='') as f:
            w = csv.writer(f)
            w.writerow(["Timestamp","Operator","Band","dBm","CID","LAC","MCC","MNC"])
            w.writerows(self._cell_log_data)
        self.cell_status.text = f"Saved: {os.path.basename(out)}"

    # ══════════════════════════════════════════════════════
    #  NET MONITOR LOGIC
    # ══════════════════════════════════════════════════════
    def toggle_net_monitor(self, instance):
        self.net_running = not self.net_running
        if self.net_running:
            self.net_btn.text = "STOP CAPTURE"
            self.net_btn.background_color = (0.7,0,0,1)
            Clock.schedule_interval(self._net_tick, 2)
        else:
            self.net_btn.text = "START CAPTURE"
            self.net_btn.background_color = (0,0.5,0.8,1)
            Clock.unschedule(self._net_tick)

    def _read_net_stats(self):
        """Try real /proc/net/dev on Android/Linux"""
        try:
            rx_total = tx_total = 0
            with open('/proc/net/dev','r') as f:
                for line in f.readlines()[2:]:
                    parts = line.split()
                    if len(parts) > 9 and parts[0] not in ('lo:',):
                        rx_total += int(parts[1])
                        tx_total += int(parts[9])
            return rx_total, tx_total
        except Exception:
            return None, None

    def _net_tick(self, dt):
        rx, tx = self._read_net_stats()
        if rx is not None:
            rx_kb = max(0, (rx - self._prev_rx) / 1024) if self._prev_rx else 0
            tx_kb = max(0, (tx - self._prev_tx) / 1024) if self._prev_tx else 0
            self._prev_rx, self._prev_tx = rx, tx
            source = "REAL"
        else:
            rx_kb = random.uniform(5, 800)
            tx_kb = random.uniform(2, 200)
            source = "SIM"

        protos = ["TCP","UDP","HTTPS","DNS","HTTP"]
        proto  = random.choice(protos)
        pkts   = random.randint(10,500)

        self.net_display.text = (
            f"RX: {rx_kb:.1f} KB/s  TX: {tx_kb:.1f} KB/s\n"
            f"Packets: {pkts}  Protocol: {proto}\n"
            f"Total Samples: {len(self._net_log_data)}\n"
            f"Source: {source}  |  {datetime.now().strftime('%H:%M:%S')}")
        self.rx_graph.push(rx_kb)
        self.tx_graph.push(tx_kb)
        self._net_log_data.append([datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                   "wlan0", rx_kb, tx_kb, pkts, proto])
        self.net_status.text = f"Capturing... {len(self._net_log_data)} records"

    def save_net_log(self, instance):
        if not self._net_log_data:
            self.net_status.text = "No data yet!"; return
        ensure_dirs()
        out = os.path.join(DATA_DIR, f"net_log_{datetime.now().strftime('%H%M%S')}.csv")
        with open(out,'w',newline='') as f:
            w = csv.writer(f)
            w.writerow(["Timestamp","Interface","RX_KB","TX_KB","Packets","Protocol"])
            w.writerows(self._net_log_data)
        self.net_status.text = f"Saved: {os.path.basename(out)}"

    # ══════════════════════════════════════════════════════
    #  MAP LOGIC
    # ══════════════════════════════════════════════════════
    def _update_gps(self, dt):
        """Try real Android GPS"""
        if ANDROID:
            try:
                LocationManager = autoclass('android.location.LocationManager')
                ctx = autoclass('org.kivy.android.PythonActivity').mActivity
                lm  = ctx.getSystemService(ctx.LOCATION_SERVICE)
                loc = lm.getLastKnownLocation(LocationManager.GPS_PROVIDER)
                if loc:
                    self._current_lat = loc.getLatitude()
                    self._current_lon = loc.getLongitude()
                    acc = loc.getAccuracy()
                    self.map_coords.text = (
                        f"LAT: {self._current_lat:.6f}\n"
                        f"LON: {self._current_lon:.6f}\n"
                        f"Accuracy: {acc:.1f}m  [GPS REAL]")
                    return
            except Exception:
                pass
        # Simulation
        self._current_lat += random.uniform(-0.0001, 0.0001)
        self._current_lon += random.uniform(-0.0001, 0.0001)
        self.map_coords.text = (
            f"LAT: {self._current_lat:.6f}\n"
            f"LON: {self._current_lon:.6f}\n"
            f"Source: {'Android GPS' if ANDROID else 'Simulation'}")

    def open_osm(self, instance):
        url = f"https://www.openstreetmap.org/?mlat={self._current_lat}&mlon={self._current_lon}&zoom=15"
        webbrowser.open(url)

    def open_gmaps(self, instance):
        url = f"https://www.google.com/maps?q={self._current_lat},{self._current_lon}"
        webbrowser.open(url)

    def set_manual_location(self, instance):
        try:
            parts = self.coord_input.text.strip().split(',')
            self._current_lat = float(parts[0].strip())
            self._current_lon = float(parts[1].strip())
            self.map_coords.text = (
                f"LAT: {self._current_lat:.6f}\n"
                f"LON: {self._current_lon:.6f}\n"
                f"Source: Manual Input")
        except Exception:
            self.map_coords.text = "LAT: ERROR\nLON: Invalid input\nFormat: 33.6844,73.0479"

    def load_map_history(self, instance):
        self.map_hist_grid.clear_widgets()
        if not os.path.exists(TOWER_CSV): return
        with open(TOWER_CSV,'r') as f:
            rows = list(csv.reader(f))
        for row in reversed(rows[1:10]):
            if len(row)<5: continue
            lbl = Label(
                text=f"{row[0]}  Tag:{row[1]}\nLAT:{row[3]} LON:{row[4]}",
                size_hint_y=None, height=60, color=(0.8,0.8,0.8,1), font_size='11sp')
            self.map_hist_grid.add_widget(lbl)

    # ══════════════════════════════════════════════════════
    #  INTEL LOGIC
    # ══════════════════════════════════════════════════════
    def run_search(self, instance):
        target = self.s_input.text.strip()
        stype  = self.search_type.text
        if not target: return
        self.grid.clear_widgets()
        self.last_results = []
        results = self._deep_search(target, stype)
        if not results:
            self.grid.add_widget(Label(
                text=f"NO MATCH FOUND\nQuery: {target}",
                size_hint_y=None, height=90, color=(1,0.3,0.3,1)))
            return
        for r in results:
            pct   = r.get('match',0)
            color = (0,1,0,1) if pct>80 else (1,0.8,0,1)
            self.grid.add_widget(Label(
                text=(f"MATCH: {pct}%\n"
                      f"Name: {r.get('Name','--')} | CNIC: {r.get('CNIC','--')}\n"
                      f"Phone: {r.get('Phone','--')} | DOB: {r.get('DOB','--')}\n"
                      f"Address: {r.get('Address','--')} | Status: {r.get('Status','--')}"),
                size_hint_y=None, height=150, color=color, halign='left'))
            self.last_results.append(r)

    def _deep_search(self, query, stype):
        results = []
        if not os.path.exists(CNIC_CSV): return results
        col_map = {'CNIC SEARCH':'CNIC','PHONE NUMBER':'Phone',
                   'NAME SEARCH':'Name','ADDRESS SEARCH':'Address'}
        col = col_map.get(stype,'CNIC')
        with open(CNIC_CSV,'r') as f:
            for row in csv.DictReader(f):
                cell = str(row.get(col,''))
                if query.lower() in cell.lower():
                    pct = min(100, int((len(query)/max(len(cell),1))*100+40))
                    row['match'] = pct
                    results.append(dict(row))
        return sorted(results, key=lambda x: x['match'], reverse=True)

    def export_results(self, instance):
        if not self.last_results:
            self.export_status.text = "No results!"; return
        ensure_dirs()
        out = os.path.join(DATA_DIR, f"export_{datetime.now().strftime('%H%M%S')}.csv")
        with open(out,'w',newline='') as f:
            w = csv.DictWriter(f, fieldnames=self.last_results[0].keys())
            w.writeheader(); w.writerows(self.last_results)
        self.export_status.text = f"Saved: {os.path.basename(out)}"

    # ══════════════════════════════════════════════════════
    #  FREQUENCY LOGIC
    # ══════════════════════════════════════════════════════
    BAND_INFO = {
        '700MHz':('JAZZ','4G-LTE'),'850MHz':('ZONG','3G-UMTS'),
        '1800MHz':('TELENOR','4G-LTE'),'2100MHz':('UFONE','3G-UMTS'),
        '2600MHz':('JAZZ','4G-LTE'),'3500MHz':('ZONG','5G-NR'),
    }

    def start_freq_scan(self, instance):
        self.freq_status.text = "Scanning..."
        Clock.schedule_once(self._do_freq_scan, 0.5)

    def _do_freq_scan(self, dt):
        summary = "FREQUENCY SCAN RESULTS:\n"
        self.scan_data = []
        for band, bar in self.freq_bars.items():
            val = random.randint(10,95)
            bar.value = val
            op, btype = self.BAND_INFO.get(band,('?','?'))
            act = "HIGH" if val>70 else "MED" if val>40 else "LOW"
            summary += f"{band}: {val}% [{act}] {op} {btype}\n"
            self.scan_data.append([datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                   band, val, act, op, btype])
        self.freq_display.text = summary
        self.freq_status.text  = f"Done {datetime.now().strftime('%H:%M:%S')}"

    def save_freq_log(self, instance):
        if not self.scan_data:
            self.freq_status.text = "Scan first!"; return
        ensure_dirs()
        with open(FREQ_CSV,'a',newline='') as f:
            csv.writer(f).writerows(self.scan_data)
        self.freq_status.text = "Frequency log saved!"

    # ══════════════════════════════════════════════════════
    #  HISTORY LOGIC
    # ══════════════════════════════════════════════════════
    def load_history(self, instance):
        self.hist_grid.clear_widgets()
        if not os.path.exists(TOWER_CSV):
            self.hist_grid.add_widget(Label(text="No history.",
                size_hint_y=None, height=70, color=(1,0.5,0,1))); return
        with open(TOWER_CSV,'r') as f:
            rows = list(csv.reader(f))
        if len(rows)<=1:
            self.hist_grid.add_widget(Label(text="Empty.",
                size_hint_y=None, height=70)); return
        for i, row in enumerate(reversed(rows[1:]),1):
            if len(row)<6: continue
            ts,tag,net,lat,lon,sig = row[0],row[1],row[2],row[3],row[4],row[5]
            band = row[8] if len(row)>8 else "?"
            self.hist_grid.add_widget(Label(
                text=f"#{i} {ts}\nTag:{tag} Net:{net} Band:{band}\nLAT:{lat} LON:{lon} Sig:{sig}dBm",
                size_hint_y=None, height=120, color=(0.8,0.8,0.8,1), halign='left'))

    def clear_history(self, instance):
        if os.path.exists(TOWER_CSV):
            with open(TOWER_CSV,'w',newline='') as f:
                csv.writer(f).writerow(["Timestamp","Tag","Network","LAT","LON",
                                        "Signal_dBm","CID","LAC","Band"])
        self.hist_grid.clear_widgets()
        self.hist_grid.add_widget(Label(text="Cleared.",
            size_hint_y=None, height=70, color=(1,0.5,0,1)))


# ╔══════════════════════════════════════════════════════════╗
# ║  APP ENTRY                                                ║
# ╚══════════════════════════════════════════════════════════╝
class KhojiApp(App):
    def build(self):
        sm = ScreenManager()
        sm.add_widget(LoginScreen(name='login'))
        sm.add_widget(Dashboard(name='dashboard'))
        return sm

if __name__ == '__main__':
    KhojiApp().run()
