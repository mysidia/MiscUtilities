/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `_info`
--

DROP TABLE IF EXISTS `_info`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `_info` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `service` enum('dialup','dsl') NOT NULL,
  `UserName` varchar(64) NOT NULL,
  `account_name` varchar(64) DEFAULT NULL,
  `site_name` varchar(64) DEFAULT NULL,
  `grp` varchar(64) NOT NULL,
  `status` enum('active','inactive','new','convert','password','suspended') DEFAULT NULL,
  `date` date DEFAULT NULL,
  `dsl_type` enum('att','cust','stnd') DEFAULT NULL,
  `down` int(11) DEFAULT NULL,
  `up` int(11) DEFAULT NULL,
  `noc_router` varchar(32) DEFAULT NULL,
  `interface` varchar(32) DEFAULT NULL,
  `encap` enum('interface','ipoa','mer','pppoa','pppoe') DEFAULT NULL,
  `ppp_name` varchar(64) NOT NULL,
  `ppp_password` varchar(32) NOT NULL,
  `cpe_gateway` varchar(32) DEFAULT NULL,
  `cpe_wan` varchar(32) NOT NULL,
  `cpe_wan_sn` varchar(32) DEFAULT '32',
  `cpe_wan_png` varchar(8) DEFAULT NULL,
  `dns_primary` varchar(32) DEFAULT NULL,
  `dns_sec` varchar(32) DEFAULT NULL,
  `pvc` varchar(16) DEFAULT NULL,
  `vlan` int(11) DEFAULT NULL,
  `clli` varchar(8) DEFAULT NULL,
  `rmt` tinyint(4) DEFAULT NULL,
  `slpt` varchar(8) DEFAULT NULL,
  `axm` varchar(4) DEFAULT NULL,
  `np` varchar(4) DEFAULT NULL,
  `pvc_2` varchar(8) DEFAULT NULL,
  `bty` varchar(8) DEFAULT NULL,
  `pair` varchar(8) DEFAULT NULL,
  `line` varchar(8) DEFAULT NULL,
  `dgn` varchar(32) DEFAULT NULL,
  `phone_number` varchar(16) DEFAULT NULL,
  `dslcircuit_id` varchar(24) DEFAULT NULL,
  `dsl_use` varchar(16) DEFAULT NULL,
  `dist` varchar(32) DEFAULT NULL,
  `bt` varchar(32) DEFAULT NULL,
  `demarc_location` varchar(200) DEFAULT NULL,
  `access` varchar(32) DEFAULT NULL,
  `cpe_modem_rtr_location` varchar(32) DEFAULT NULL,
  `cpe_modem_rtr` varchar(32) DEFAULT NULL,
  `serial_nr` varchar(32) DEFAULT NULL,
  `port` varchar(32) DEFAULT NULL,
  `name` varchar(32) DEFAULT NULL,
  `password` varchar(32) DEFAULT NULL,
  `mode` varchar(32) DEFAULT NULL,
  `cpe_lan_ip` varchar(32) DEFAULT NULL,
  `cpe_lan_sn` varchar(32) DEFAULT NULL,
  `dhcp` varchar(32) DEFAULT NULL,
  `user_wan_addr` varchar(32) DEFAULT NULL,
  `user_wan_sn` varchar(32) DEFAULT NULL,
  `user_wan_png` varchar(32) DEFAULT NULL,
  `user_router` varchar(32) DEFAULT NULL,
  `notes` varchar(255) DEFAULT NULL,
  `hrs` varchar(16) DEFAULT NULL,
  `dbcustkey` varchar(64) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `dbkey` (`dbcustkey`),
  UNIQUE KEY `dbcustkey` (`dbcustkey`)
) ENGINE=InnoDB AUTO_INCREMENT=829 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!50003 SET @saved_cs_client      = @@character_set_client */ ;
/*!50003 SET @saved_cs_results     = @@character_set_results */ ;
/*!50003 SET @saved_col_connection = @@collation_connection */ ;
/*!50003 SET character_set_client  = utf8 */ ;
/*!50003 SET character_set_results = utf8 */ ;
/*!50003 SET collation_connection  = utf8_general_ci */ ;
/*!50003 SET @saved_sql_mode       = @@sql_mode */ ;
/*!50003 SET sql_mode              = 'NO_ENGINE_SUBSTITUTION' */ ;
DELIMITER ;;
/*!50003 CREATE*/ /*!50017 DEFINER=`root`@`localhost`*/ /*!50003 trigger before__info_ins BEFORE INSERT on _info FOR EACH ROW set new.dbcustkey = uuid() */;;
DELIMITER ;
/*!50003 SET sql_mode              = @saved_sql_mode */ ;
/*!50003 SET character_set_client  = @saved_cs_client */ ;
/*!50003 SET character_set_results = @saved_cs_results */ ;
/*!50003 SET collation_connection  = @saved_col_connection */ ;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;
