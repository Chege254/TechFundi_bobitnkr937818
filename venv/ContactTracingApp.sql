-- phpMyAdmin SQL Dump
-- version 4.8.5
-- https://www.phpmyadmin.net/
--
-- Host: localhost
-- Generation Time: Aug 05, 2020 at 02:29 PM
-- Server version: 10.1.38-MariaDB
-- PHP Version: 7.1.26

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET AUTOCOMMIT = 0;
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `martdevelopers_ContactTracingApp`
--

-- --------------------------------------------------------

--
-- Table structure for table `questionaires`
--

CREATE TABLE `questionaires` (
  `id` int(20) NOT NULL,
  `name` varchar(200) NOT NULL,
  `age` varchar(200) NOT NULL,
  `phone` longtext NOT NULL,
  `symptoms` longtext NOT NULL,
  `symptops_started` longtext NOT NULL,
  `closeness` longtext NOT NULL,
  `other_medical_issues` longtext NOT NULL,
  `family_members` longtext NOT NULL,
  `any_recent_travel` longtext NOT NULL,
  `same_symptoms` longtext NOT NULL,
  `create_date` timestamp(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `questionaires`
--

INSERT INTO `questionaires` (`id`, `name`, `age`, `phone`, `symptoms`, `symptops_started`, `closeness`, `other_medical_issues`, `family_members`, `any_recent_travel`, `same_symptoms`, `create_date`) VALUES
(1, 'Mart Mbithi', '20', '+254 743 733706', 'Symptoms are chills, fever and sweating, usually occurring a few weeks after being bitten.\r\n', 'Three weeks ago that is 30th July 2020', 'No ', 'Yes, Symptoms are chills, fever and sweating, usually occurring a few weeks after being bitten.\r\n', '4', 'Yes, I travelled Home from town', 'No', '2020-08-05 11:04:00.008994'),
(2, 'MartMbithi', '56', '+254723473411', 'Symptoms are chills, fever and sweating, usually occurring a few weeks after being bitten.\r\n', 'Three weeks ago that is 30th July 2020', 'Yes, On 1st August 2020', 'No', '4', 'Yes , From Nairobi to Machakos', 'Yes, My brother has fever and sweating,', '2020-08-05 11:12:06.411307');

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` int(20) NOT NULL,
  `name` varchar(200) NOT NULL,
  `email` varchar(200) NOT NULL,
  `username` varchar(200) NOT NULL,
  `password` varchar(200) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `name`, `email`, `username`, `password`) VALUES
(1, 'Martin', 'martinezmbithi@gmail.com', 'mart', '$5$rounds=535000$0XqrU7X1Uim2Vd89$QhWdhd2iMrsAC2KcAG1sFTnGfvKBg4EEmmVFBzexOQ0'),
(2, 'Mart Mbithi', 'martdevelopers254@gmail.com', 'Mart Mbithi', '$5$rounds=535000$mmJ5eKr9dDI/JKcw$In4JWdIXya8XzjhL4LoJKIrB2ttIvsWoY3IVPqKzZLB'),
(3, 'mercy mumo', 'martdevelopers@ilib.org', 'Mercy', '$5$rounds=535000$0zZ2L5Ns6vXIhWie$KdldRxHyjup1BfqGv.hyk1GRULp4pzYIM5du11H7Yi3');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `questionaires`
--
ALTER TABLE `questionaires`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `questionaires`
--
ALTER TABLE `questionaires`
  MODIFY `id` int(20) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` int(20) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
