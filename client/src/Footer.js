import React from 'react';

const Footer = () => {
  const today = new Date();

  return (
    <footer>
      Copyright &copy; {today.getFullYear()}
    </footer>
  );
}

export default Footer;
