if (window.rcmail) {
  rcmail.addEventListener('init', function(evt) {
    duo_row = '<tr> \
                 <td class="title"> \
                   <label for="rcmloginduopasscode">' + rcmail.get_label('duo_authentication.passcode') + '</label> \
                 </td> \
                 <td class="input"> \
                   <input name="_duopasscode" style="width: 200px;" id="rcmloginduopasscode" autocomplete="off" type="text"> \
                 </td> \
               </tr>';
    document.getElementsByName('form')[0].getElementsByTagName('table')[0].getElementsByTagName('tbody')[0].innerHTML += duo_row;
  });
}
