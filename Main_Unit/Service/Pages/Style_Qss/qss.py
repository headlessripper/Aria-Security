qss = """
    * {
        font-family: "Segoe UI", -apple-system, BlinkMacSystemFont, system-ui;
        color: #e5e7eb;
        font-size: 13px;
    }

    #Outer { background: transparent; }
    #Shell {
        background: qradialgradient(cx:0.1, cy:0, radius:1,
                                    fx:0.1, fy:0,
                                    stop:0 #0e0e0e, stop:1 #3e3e3e);
        border-radius: 28px;
        border: 1px solid #000000;
    }

    #Sidebar {
        background-color: rgba(15,23,42,0.96);
        border-radius: 22px;
        border: 1px solid rgba(30,64,175,0.35);
    }
    #Center {
        border-radius: 22px;
        background-color: #0e0e0e;
    }

    #HeaderBar {
        background-color: #0e0e0e;
        border-radius: 22px;
        border: 1px solid #000000;
    }
    #GraphCard {
        background-color: #1e1e1e;
        border-radius: 24px;
        border: 1px solid #000000;
    }
    #BottomStats { background: transparent; }
    #BottomTile {
        background-color: #000000;
        border-radius: 16px;
        border: 1px solid #000000;
    }

    QLabel { background: transparent; }

    #LogoLabel {
        font-size: 18px;
        font-weight: 600;
    }
    #StatusDot {
        color: #22c55e;
        font-size: 12px;
    }
    #HeaderTitle {
        font-size: 18px;
        font-weight: 600;
    }
    #HeaderBreadcrumb {
        font-size: 11px;
        color: #9ca3af;
    }
    #GraphTitle {
        font-size: 14px;
        font-weight: 500;
    }
    #GraphSubtitle {
        font-size: 11px;
        color: #9ca3af;
    }

    QLabel[statTitle="true"] {
        font-size: 11px;
        color: #9ca3af;
    }
    QLabel[statValue="true"] {
        font-size: 20px;
        font-weight: 600;
    }
    QLabel[statValueSmall="true"] {
        font-size: 14px;
        font-weight: 500;
    }
    #PageTitle {
        font-size: 16px;
        font-weight: 600;
    }
    #PageHint {
        font-size: 12px;
        color: #9ca3af;
    }

    QPushButton[nav="true"] {
        background: transparent;
        border-radius: 999px;
        padding: 8px 14px;
        text-align: left;
        color: #9ca3af;
        border: none;
    }
    QPushButton[nav="true"]:hover {
        background-color: rgba(31,41,55,0.7);
        color: #e5e7eb;
    }
    QPushButton[nav="true"]:checked {
        background-color: rgba(31,41,55,1.0);
        color: #e5e7eb;
    }

    #SegmentContainer {
        background-color: #000000;
        border-radius: 8px;
        border: 1px solid #000000;
    }
    QPushButton#Segment {
        background: transparent;
        border-radius: 16px;
        padding: 6px 18px;
        color: #9ca3af;
        border: none;
        font-size: 13px;
    }
    QPushButton#Segment[active="true"] {
        background-color: #0e0e0e;
        color: #e5e7eb;
    }
    QPushButton#Segment:hover {
        background-color: #1e1e1e;
    }

    QPushButton#FilterChip {
        background-color: #000000;
        border-radius: 16px;
        border: 1px solid #000000;
        padding: 4px 10px;
        font-size: 11px;
        color: #9ca3af;
    }
    QPushButton#FilterChip[active="true"] {
        background-color: #000000;
        border-color: #000000;
        color: #e5e7eb;
        border-radius: 16px;
    }

    QGraphicsView {
        background: transparent;
        border: none;
    }
    
    #InterfaceCard, #TracerouteCard {
        background-color: #0e0e0e;
        border-radius: 16px;
        border: transparent;
    }

    #InterfaceList {
        border: none;
        background: transparent;
    }

    #InterfaceItemCard {
        background-color: #020617;
        border-radius: 10px;
        border: 1px solid rgba(31,41,55,0.9);
    }

    #InterfaceItemCard:hover {
        border-color: rgba(59,130,246,0.9);
        background-color: #030712;
    }

    #InterfaceName {
        font-size: 13px;
        font-weight: 500;
    }

    #InterfaceHint {
        font-size: 11px;
        color: #9ca3af;
    }

    #MapPlaceholder {
        font-size: 12px;
        color: #9ca3af;
    }
    
    #TracerouteMap {
        background-color: #0e0e0e;
        border-radius: 16px;
        border: 1px solid #000000;
    }

    #TracerouteWebView {
        border-radius: 16px;
        background: transparent;
    }

        /* --- Global --- */
    
    /* Page background */
    AlertsPage {
        background-color: transparent;
    }

    /* Titles and hints */
    QLabel#PageTitle {
        font-size: 20px;
        font-weight: 600;
        color: #f9fafb;
    }

    QLabel#SectionTitle {
        font-size: 14px;
        font-weight: 600;
        color: #e5e7eb;
    }

    QLabel#PageHint {
        font-size: 11px;
        color: #9ca3af;
    }

    /* Cards */
    QWidget#SideCard {
        background-color: #000000;
        border-radius: 14px;
        border: 1px solid #000000;
        padding: 8px;
    }

    QWidget#SideCard:hover {
        border-color: #1e1e1e;
    }

    /* Storage visualizer wrapper */
    #StorageVisualizerBar {
        margin-top: 4px;
        margin-bottom: 4px;
    }

    /* Buttons */
    QPushButton#SmallButton {
        background-color: #1e1e1e;
        border-radius: 8px;
        border: transparent;
        padding: 4px 10px;
        color: #e5e7eb;
    }

    QPushButton#SmallButton:hover {
        background-color: #3e3e3e;
    }

    QPushButton#SmallButton:pressed {
        background-color: #0e0e0e;
    }

    /* Progress bar */
    QProgressBar {
        background-color: #3e3e3e;
        border-radius: 8px;
        border: transparent;
        text-align: center;
        color: #9ca3af;
    }

    QProgressBar::chunk {
        background-color: qlineargradient(
            x1:0, y1:0, x2:1, y2:0,
            stop:0 #3b82f6,
            stop:1 #6366f1
        );
        border-radius: 7px;
    }

    /* Duplicate list */
    QListWidget#StorageDupList {
        background-color: #0e0e0e;
        border-radius: 10px;
        border: 1px solid transparent;
        padding: 6px;
    }

    QListWidget#StorageDupList::item {
        color: #d1d5db;
        padding: 2px 4px;
    }

    QListWidget#StorageDupList::item:selected {
        background-color: #1f2937;
    }
    
    /* Header icon buttons */
    #IconButton, #closeButton {
        background-color: #18181b;
        color: #e5e7eb;
        border: 1px solid #27272a;
        border-radius: 8px;
        font-size: 14px;
    }
    #IconButton:hover, #closeButton:hover {
        background-color: #27272a;
    }
    #IconButton:pressed, #closeButton:pressed {
        background-color: #0f172a;
    }
    
    /* Table */
    QTableWidget {
        background-color: transparent;
        border: none;
        gridline-color: #111827;
        color: #e5e7eb;
        selection-background-color: rgba(56, 189, 248, 0.18);
        selection-color: #f9fafb;
    }
    QHeaderView::section {
        background-color: #0e0e0e;
        color: #9ca3af;
        padding: 6px 8px;
        border: none;
        border-bottom: 1px solid #111827;
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 0.1em;
    }

    /* Vertical Scrollbar */
    QScrollArea {
        background-color: transparent;  /* <-- change this to your desired color */
        border: none;
    }

    QScrollArea QWidget {  /* viewport content */
        background-color: transparent;  /* same as scroll area or slightly different */
    }
    QScrollBar:vertical {
        background: transparent;
        width: 8px;
        margin: 0px;
        border: none;
    }

    QScrollBar::handle:vertical {
        background: #ffffff;
        min-height: 20px;
        border-radius: 4px;
    }

    QScrollBar::handle:vertical:hover {
        background: #1b1b1b;
    }

    QScrollBar::add-line:vertical,
    QScrollBar::sub-line:vertical,
    QScrollBar::add-page:vertical,
    QScrollBar::sub-page:vertical {
        background: none;
        height: 0px;
        border: none;
    }

    /* Horizontal Scrollbar */
    QScrollBar:horizontal {
        background: transparent;
        height: 8px;
        margin: 0px;
        border: none;
    }

    QScrollBar::handle:horizontal {
        background: rgba(0, 0, 0, 0.2);
        min-width: 20px;
        border-radius: 4px;
    }

    QScrollBar::handle:horizontal:hover {
        background: rgba(0, 0, 0, 0.4);
    }

    QScrollBar::add-line:horizontal,
    QScrollBar::sub-line:horizontal,
    QScrollBar::add-page:horizontal,
    QScrollBar::sub-page:horizontal {
        background: none;
        width: 0px;
        border: none;
    }

    /* Tooltip */
    QToolTip {
        background-color: #000000;
        color: white;
        border: 1px solid #444;
        padding: 6px;
        font-size: 12px;
        font-family: Consolas, monospace;
        border-radius: 4px;
    }
    
    QPushButton[variant="primary"] {
        background-color: #0ea5e9;
        border-color: #0ea5e9;
        color: #020617;
    }
    QPushButton[variant="primary"]:hover {
        background-color: #38bdf8;
    }
    QPushButton[variant="destructive"] {
        background-color: #000000;
        border-color: transparent;
        border-radius: 16px;
        color: #ffffff;
    }
    QPushButton[variant="destructive"]:hover {
        background-color: #1e1e1e;
    }

    """