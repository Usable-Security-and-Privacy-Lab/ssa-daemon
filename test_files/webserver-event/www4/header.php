<?php
function showMenu() {
	global $items;
	$currentSection = 'Sneakers';
	if (isset($_GET['s'])) {
		$currentSection = $_GET['s'];
	}

	$pageKeys = array_keys($items);
	foreach ($pageKeys as $key) {
		if ($key == $currentSection) {
			echo '<li class="active menu-item"><a href="/?s=', $key, '">', $key ,'</a></li>';
		}
		else if ($key == 'Commanders') {
		
		}
		else {
			echo '<li class="menu-item"><a href="/?s=', $key, '">', $key ,'</a></li>';
		}
	}
}
?>
<!DOCTYPE html>
<html lang="en">
<link rel="icon" href="favicon.ico" type="image/x-icon">
<link rel="shortcut icon" href="favicon.ico" type="image/x-icon">
<head>
  <title>PayMore</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css">
  <script src="/jquery-3.3.1.min.js"></script>
  <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"></script>
  <style>
    /* Remove the navbar's default rounded borders and increase the bottom margin */ 
    .navbar {
      margin-bottom: 30px;
      border-radius: 0;
      min-height:80px !important;
    }

    .navbar-nav>li>a {
      line-height:44px;
    }

    /*
    .navbar a {
        font-size: 1.8em;
    }
    */

    .menu-item {
        font-size: 1.5em;
    }

    .menu-account-item {
        font-size: 1.2em;
    }

    /* Remove the jumbotron's default bottom margin */ 
     .jumbotron {
      margin-bottom: 0;
    }

    .total {
      font-weight:bold;
      text-align:right;
    }

    .table>tbody>tr>td,
    .table>tfoot>tr>td {
      vertical-align:middle !important;
    }

     .navbar-brand img {
      height:44px;
    }

    header {
      /*background-color: #f2f2f2;*/
      background: linear-gradient(to bottom, #f2f2f2 0%, #dddddd 100%);
    }
   
    /* Add a gray background color and some padding to the footer */
    footer {
      background-color: #f2f2f2;
      padding: 25px;
    }
  </style>
</head>
<body>

<!--<div class="jumbotron">
  <div class="container text-center">
    <h1>Congo</h1>      
    <p>Mission, Vission & Values</p>
  </div>
</div>-->

<nav class="navbar navbar">
  <header class="container-fluid">
    <div class="navbar-header">
      <button type="button" class="navbar-toggle" data-toggle="collapse" data-target="#myNavbar">
        <span class="icon-bar"></span>
        <span class="icon-bar"></span>
        <span class="icon-bar"></span>                        
      </button>
      <a class="navbar-brand" href="/"><img src="/logo.png" alt="PayMore" /></a>
    </div>
    <div class="collapse navbar-collapse" id="myNavbar">
      <ul class="nav navbar-nav">
        <?php showMenu(); ?>
      </ul>
      <ul class="nav navbar-nav navbar-right">
	<li class="menu-account-item"><a href="/account/"><span class="glyphicon glyphicon-user"></span>
		<?php 
		if(isset($_SESSION['name'])){
			echo "Welcome ".$_SESSION['name'];
		}else{ 
		?>
			Register
		<?php
		 } 
		?>
		</a></li>
        <li class="menu-account-item"><a href="/cart/"><span class="glyphicon glyphicon-shopping-cart"></span>Cart</a></li>
      </ul>
    </div>
  </div>
</nav>
