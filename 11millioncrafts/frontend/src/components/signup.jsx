import React, { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import '../index.css';

function Signup() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('User'); // Default role is User
  const [message, setMessage] = useState(''); // State to hold messages
  const [error, setError] = useState(false); // State to differentiate success and error messages
  const navigate = useNavigate();

  const handleSignup = async (e) => {
    e.preventDefault();
    setMessage(''); // Clear any previous messages
    try {
      const response = await axios.post(
        'http://localhost:5001/register', // Correct backend port
        { email, password, role },
        {
          headers: { 'Content-Type': 'application/json' }, // Explicitly set headers
        }
      );
      setMessage(response.data.message);
      setError(false); // Mark as success
      setTimeout(() => navigate('/login'), 2000); // Redirect to login after 2 seconds
    } catch (error) {
      setMessage(error.response?.data?.message || 'An error occurred.');
      setError(true); // Mark as error
    }
  };

  return (
    <div className="form-container">
      <form onSubmit={handleSignup}>
        <h2>Sign Up</h2>
        <input
          type="email"
          placeholder="Enter your email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
        />
        <input
          type="password"
          placeholder="Enter your password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
        <select value={role} onChange={(e) => setRole(e.target.value)} required>
          <option value="User">User</option>
          <option value="Admin">Admin</option>
        </select>
        <button type="submit">Register</button>
        {/* Display success or error message */}
        {message && (
          <p className={error ? 'error-message' : 'success-message'}>
            {message}
          </p>
        )}
      </form>
    </div>
  );
}

export default Signup;
