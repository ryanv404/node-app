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

const star_1 = document.getElementById("stars-1");
const star_2 = document.getElementById("stars-2");
const star_3 = document.getElementById("stars-3");
const star_4 = document.getElementById("stars-4");
const star_5 = document.getElementById("stars-5");
const edit_star_1 = document.getElementById("edit_stars-1");
const edit_star_2 = document.getElementById("edit_stars-2");
const edit_star_3 = document.getElementById("edit_stars-3");
const edit_star_4 = document.getElementById("edit_stars-4");
const edit_star_5 = document.getElementById("edit_stars-5");

const star_list = [star_1, star_2, star_3, star_4, star_5];
const edit_star_list = [
  edit_star_1,
  edit_star_2,
  edit_star_3,
  edit_star_4,
  edit_star_5,
];

const filledClasses = "fas fa-star text-warning";
const unfilledClasses = "far fa-star";

const displayRating = (stars) => {
  stars.forEach((star) => {
    star.onclick = () => {
      let i = stars.indexOf(star);
      const stars_length = stars.length;

      if (star.className === unfilledClasses) {
        for (i; i >= 0; i--) {
          stars[i].className = filledClasses;
        }
        // Allow for zero star rating if already set to 1 star
      } else if (
        star.className === filledClasses &&
        i === 0 &&
        stars[i + 1].className === unfilledClasses
      ) {
        for (i; i < stars_length; i++) {
          stars[i].className = unfilledClasses;
        }
      } else {
        i += 1;
        for (i; i < stars_length; i++) {
          stars[i].className = unfilledClasses;
        }
      }
    };
  });
};

const editDisplayRating = (stars) => {
  stars.forEach((star) => {
    star.onclick = () => {
      let i = stars.indexOf(star);
      const stars_length = stars.length;

      const ratingRadioID = "edit-check-" + String(i + 1);
      console.log(ratingRadioID);
      document.getElementById(ratingRadioID).checked = true;
      if (star.className === unfilledClasses) {
        for (i; i >= 0; i--) {
          stars[i].className = filledClasses;
        }
        // Allow for zero star rating if already set to 1 star
      } else if (
        star.className === filledClasses &&
        i === 0 &&
        stars[i + 1].className === unfilledClasses
      ) {
        for (i; i < stars_length; i++) {
          stars[i].className = unfilledClasses;
        }
      } else {
        i += 1;
        for (i; i < stars_length; i++) {
          stars[i].className = unfilledClasses;
        }
      }
    };
  });
};
displayRating(star_list);
editDisplayRating(edit_star_list);

const edit_modal = document.getElementById("edit_review_modal");
edit_modal.addEventListener("show.bs.modal", (event) => {
  const btn = event.relatedTarget;
  const revID = btn.getAttribute("data-bs-reviewID");

  function run() {
    const xhr = new XMLHttpRequest();
    const url = "http://localhost:3000/reviews/" + revID;

    xhr.open("GET", url, true);

    xhr.onreadystatechange = function () {
      if (this.readyState == 4 && this.status == 200) {
        const newReview = JSON.parse(this.responseText);
        document.getElementById("edit_movieTitle").value = newReview.movieName;
        document.getElementById("edit_reviewTitle").value =
          newReview.reviewTitle;
        document.getElementById("edit_reviewContent").value =
          newReview.reviewBody;
        const put_link = "/reviews/" + String(newReview._id) + "/?_method=PUT";
        document.getElementById("edit-form").setAttribute("action", put_link);

        if (newReview.reviewRating != 0) {
          const ratingID = "edit-check-" + String(newReview.reviewRating);
          document.getElementById(ratingID).checked = true;
          let i = Number(newReview.reviewRating) - 1;
          for (i; i >= 0; i--) {
            edit_star_list[i].className = filledClasses;
          }
        }
      }
    };
    xhr.send();
  }
  if (revID) {
    run();
  }
});