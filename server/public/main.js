const register_btn = document.querySelector("#register_btn");
const login_btn = document.querySelector("#login_btn");

const signin_body = document.querySelector("#sign-in");
const signin_tab = document.querySelector("#sign-in-tab");
const register_body = document.querySelector("#register");
const register_tab = document.querySelector("#register-tab");

register_btn.addEventListener("click", () => {
  if (signin_tab.classList.contains("active")) {
    signin_body.classList.toggle("show");
    signin_body.classList.toggle("active");
    signin_tab.classList.toggle("active");
    register_body.classList.toggle("show");
    register_body.classList.toggle("active");
    register_tab.classList.toggle("active");
  }
});

login_btn.addEventListener("click", () => {
  if (!signin_tab.classList.contains("active")) {
    signin_body.classList.toggle("show");
    signin_body.classList.toggle("active");
    signin_tab.classList.toggle("active");
    register_body.classList.toggle("show");
    register_body.classList.toggle("active");
    register_tab.classList.toggle("active");
  }
});
