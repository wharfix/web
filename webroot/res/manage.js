
  let validateForm = function() {
    let button = $("button");
    let mark = true;
    $(".form-control").each(function() {
      if (!($(this).hasClass('is-valid'))) {
	button.prop('aria-disabled', true);
	button.prop('disabled', true);
	button.addClass('disabled');
        mark = false;	
      }
    });

    if (mark) {
      button.prop('aria-disabled', false);
      button.prop('disabled', false);
      button.removeClass('disabled');
    }
  };

$(function() {
  $("input.form-control").keyup(function() {
    const $that = $(this);
    const patt = new RegExp($that.data('pattern'));
    if (patt.test($that.val())) {
      $that.removeClass('is-invalid');
      $that.addClass('is-valid');
    } else {
      $that.removeClass('is-valid');
      $that.addClass('is-invalid');
    }
    validateForm();
  });

  $("#registry-name").keyup(function() {
    const display = $("#registry-name-display");
    display.text($(this).val() + ".wharfix.dev");
    if ($(this).hasClass('is-invalid')) {
      display.addClass('is-invalid');
    } else {
      display.removeClass('is-invalid');
    }
  });
});;
