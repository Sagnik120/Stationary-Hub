# 📦 Stationery Hub

> A modern, interactive web platform for ordering stationery supplies powered by an intelligent chatbot and smooth visual micro-interactions.

---

## 🌟 Key Features

- **Cinematic Hero Experience**: Lightweight, high-performance looping background video with dynamic cursor spotlight.
- **Micro-Interactive Product Gallery**: Interactive product cards featuring smooth image-to-video crossfade on hover with automatic playback management.
- **Interactive Carousel**: Responsive 3D coverflow carousel showcasing featured products powered by Swiper.js.
- **Modular Authentication**: Clean split-panel sign-in and sign-up interface with client-side form validation.
- **FastAPI Chatbot Backend**: Python backend integrated with Dialogflow for conversation-based ordering.
- **Optimized Media Assets**: Web-optimized H.264 video streams and compressed imagery ensuring ultra-fast page load times and zero Git/deployment size bottlenecks.

---

## 🏗️ Project Architecture

```
Stationary-Hub/
├── README.md                      # Project overview and setup documentation
├── .gitattributes                 # Cross-platform line ending & binary asset rules
├── .gitignore                     # Git ignore rules for node_modules, logs, and temp files
│
├── frontend/                      # Web application frontend
│   ├── index.html                 # Main landing page & product catalog
│   ├── login.html                 # User authentication (Login & Registration)
│   ├── package.json               # Node.js project metadata
│   │
│   └── assets/                    # Static assets
│       ├── css/
│       │   ├── style.css          # Main stylesheet (layout, typography, animations)
│       │   └── login.css          # Authentication stylesheet
│       ├── js/
│       │   ├── script.js          # Main scripts (Locomotive Scroll, GSAP, hover playback)
│       │   └── login.js           # Auth panel toggle & form validation
│       ├── icons/
│       │   └── favicon.svg        # Vector Stationery Hub favicon
│       ├── images/
│       │   ├── products/          # Product thumbnail covers
│       │   ├── slider/            # Coverflow slider images
│       │   └── ui/                # UI textures, backgrounds, and badges
│       └── videos/
│           ├── hero/              # Hero background video (home-bg-video.mp4)
│           └── products/          # Product hover preview video loops
│
├── backend/                       # Python FastAPI backend service
│   ├── main.py                    # API entrypoint & Dialogflow webhook handler
│   ├── db_helper.py               # MySQL database queries and transaction helpers
│   ├── generic_helper.py          # Session parsing & order formatting utilities
│   ├── requirements.txt           # Python backend dependencies
│   └── extra/                     # Additional helper utilities
│
├── dialogflow_assets/             # Chatbot intents and training phrases
│
└── archive/                       # Archived legacy prototypes
    └── legacy_frontend/          # Initial static prototype
```

---

## 🚀 Quick Start Guide

### 1. Frontend Development

To run the frontend locally:

```bash
# Using Python's built-in HTTP server:
python3 -m http.server 8080 --directory frontend

# Or using Node.js npx serve:
npx serve frontend -l 8080
```

Then open your browser to **http://localhost:8080**.

---

### 2. Backend Setup

#### Prerequisites
- Python 3.10+
- MySQL Server

#### Installation & Run
```bash
# 1. Navigate to backend directory
cd backend

# 2. Install dependencies
pip install -r requirements.txt

# 3. Start the FastAPI development server
uvicorn main:app --reload --port 8000
```

The FastAPI Swagger documentation will be available at **http://localhost:8000/docs**.

---

## 🛠️ Technology Stack

| Domain | Technologies |
| :--- | :--- |
| **Frontend UI** | HTML5, CSS3, Vanilla JavaScript (ES6+) |
| **Animations & Effects** | GSAP 3, ScrollTrigger, Locomotive Scroll |
| **Carousels** | Swiper.js (Coverflow Effect) |
| **Backend API** | FastAPI, Uvicorn, Python 3 |
| **Database** | MySQL (Connector Python) |
| **Chatbot Integration**| Google Dialogflow |

---

## 📄 License
This project is for educational and portfolio demonstration purposes.
