function locoScroll(){
    gsap.registerPlugin(ScrollTrigger);

    // Using Locomotive Scroll from Locomotive https://github.com/locomotivemtl/locomotive-scroll
    
    const locoScroll = new LocomotiveScroll({
      el: document.querySelector("#main"),
      smooth: true
    });
    // each time Locomotive Scroll updates, tell ScrollTrigger to update too (sync positioning)
    locoScroll.on("scroll", ScrollTrigger.update);
    
    // tell ScrollTrigger to use these proxy methods for the ".smooth-scroll" element since Locomotive Scroll is hijacking things
    ScrollTrigger.scrollerProxy("#main", {
      scrollTop(value) {
        return arguments.length ? locoScroll.scrollTo(value, 0, 0) : locoScroll.scroll.instance.scroll.y;
      }, // we don't have to define a scrollLeft because we're only scrolling vertically.
      getBoundingClientRect() {
        return {top: 0, left: 0, width: window.innerWidth, height: window.innerHeight};
      },
      // LocomotiveScroll handles things completely differently on mobile devices - it doesn't even transform the container at all! So to get the correct behavior and avoid jitters, we should pin things with position: fixed on mobile. We sense it by checking to see if there's a transform applied to the container (the LocomotiveScroll-controlled element).
      pinType: document.querySelector("#main").style.transform ? "transform" : "fixed"
    });
    // each time the window updates, we should refresh ScrollTrigger and then update LocomotiveScroll. 
    ScrollTrigger.addEventListener("refresh", () => locoScroll.update());
    
    // after everything is set up, refresh() ScrollTrigger and update LocomotiveScroll because padding may have been added for pinning, etc.
    ScrollTrigger.refresh();
}
locoScroll()
function cursorEffect(){
    var page1Content=document.querySelector("#page1-content")
var cursor=document.querySelector("#cursor")

page1Content.addEventListener("mousemove",function(dets){
    gsap.to(cursor,{
        x:dets.x,
        y:dets.y
    })
});

page1Content.addEventListener("mouseenter",function(dets){
    gsap.to(cursor,{
        scale:1,
        capacity:1
    })
});

page1Content.addEventListener("mouseleave",function(){
    gsap.to(cursor,{
       scale:0,
       capacity:0
    })
});
}
cursorEffect()
function page2Animation(){
    gsap.from(".elem h1",{
        y:120,
        stagger:0.2,
        duration:1,
        scrollTrigger:{
            trigger:"#page2",
            scroller:"#main",
            start:"top 40%",
            end:"top 37%", 
            scrub:2
        }
    })
}
page2Animation()
function swiper()
{
    
    var swiper = new Swiper(".mySwiper", {
        slidesPerView: 1,
        spaceBetween: 30,
        loop: true,
        autoplay: {
            delay: 2500,
            disableOnInteraction: true,
          },
      });
}

function loader()
{
    var tl=gsap.timeline()

    tl.from("#loader h3",{
        x:40,
        opacity:0,
        duration:1,
        stagger:0.3
    })
    
    tl.to("#loader h3",{
        opacity:0,
        x:-20,
        duration:1,
        stagger:0.1
    })
    tl.to("#loader",{
        opacity:0,
    })
    tl.from("#page1-content h1 span",{
        y:100,
        opacity:0,
        stagger:0.2,
        duration:0.5,
        delay:-0.5
    })
    tl.to("#loader",{
        display: "none"
    })
    
}
loader()


var swiper = new Swiper(".mySwiper", {
    effect: "coverflow",
    grabCursor: true,
    centeredSlides: true,
    slidesPerView: "auto",
    coverflowEffect: {
      rotate: 50,
      stretch: 0,
      depth: 100,
      modifier: 1,
      slideShadows: true,
    },
    pagination: {
      el: ".swiper-pagination",
    },
    loop: true,
        autoplay: {
            delay: 2500,
            disableOnInteraction: false,
          },
  });

function boxVideoHover() {
    const boxes = document.querySelectorAll("#page3-elements .box");
    boxes.forEach((box) => {
        const video = box.querySelector("video");
        if (!video) return;
        box.addEventListener("mouseenter", () => {
            video.currentTime = 0;
            video.play().catch(() => {});
        });
        box.addEventListener("mouseleave", () => {
            video.pause();
        });
    });
}
boxVideoHover();

function checkAuthStatus() {
    const authLink = document.getElementById("auth-link");
    const userStr = sessionStorage.getItem("user");
    const accessToken = sessionStorage.getItem("access_token");

    if (userStr && accessToken && authLink) {
        try {
            const user = JSON.parse(userStr);
            const parentElement = authLink.parentElement;
            parentElement.innerHTML = `
                <span style="font-size: 1.2vw; color: #4fc1de; font-weight: 500;">Hi, ${user.name}</span>
                <a href="#" id="logout-btn" style="text-decoration: none; color: #ffffff; font-size: 1.2vw; margin-left: 12px; opacity: 0.85;">Logout</a>
            `;
            const logoutBtn = document.getElementById("logout-btn");
            if (logoutBtn) {
                logoutBtn.addEventListener("click", (e) => {
                    e.preventDefault();
                    sessionStorage.clear();
                    window.location.reload();
                });
            }
        } catch (e) {
            sessionStorage.clear();
        }
    }
}
checkAuthStatus();