
  let validateForm = function() {
    $("input.form-control").each(function() {
      const $that = $(this);
      const patt = new RegExp($that.data('pattern'));
      if (patt.test($that.val())) {
        $that.removeClass('is-invalid');
        $that.addClass('is-valid');
      } else {
        $that.removeClass('is-valid');
        $that.addClass('is-invalid');
      }
    });

    const input = $("#registry_name");
    const display = $("#registry-name-display");
    display.text(input.val() + ".wharfix.dev");
    if (input.hasClass('is-invalid')) {
      display.addClass('is-invalid');
    } else {
      display.removeClass('is-invalid');
    }

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
    return mark;
  };

$(function() {

  validateForm();

  $("button").click(function() {
    $("form").submit();
  });

  $("form").submit(function() {
    $('input[type="checkbox"]').each(function() {
      let $that = $(this);
      $that.val($that.prop("checked"));
    });
    return validateForm();
  });

  $("input.form-control").keyup(validateForm);

});
