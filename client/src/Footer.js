import React from 'react';

function Footer() {
  const today = new Date();

  return (
    <footer>
      Copyright &copy; {today.getFullYear()}
    </footer>
  );
}

export default Footer;
