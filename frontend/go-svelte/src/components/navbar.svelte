<script>
    import logo from '../static/logo.png'
</script>

<nav>
    <div class="logo">
        <div class="container">
            <a href="/" title="UrlBox Logo">
                <img src={logo} alt="UrlBox Logo">
            </a>
        </div>
    </div>
    <ul>
        <div>
            <li><a href="/">Features</a></li>
            <li><a href="/">Solutions</a></li>
            <li><a href="/">Pricing</a></li>
            <li><a href="/">About</a></li>
        </div>
        <div>
            <li><a href="/">Login</a></li>
            <li><a href="/">Get a free account</a></li>
        </div>
    </ul>
</nav>

<style lang=scss>

    nav {
        display: flex;
        width: 100%;
        height: 8vh;
        background: $primary-color;

        .logo {
            display: flex;
            justify-content: center;
            align-items: center;
            flex: 1;
            background: yellow;

            .container {
                width: 2.5rem;

                a {
                    text-decoration: none;

                    img {
                        width: 100%;
                    }
                }
            }
        }

        ul {
            display: flex;
            flex: 7;
            list-style: none;

            div:nth-child(1) {
                display: flex;
                align-items: center;
                gap: 2em;
                flex: 6;

                li {
                    a {
                        text-decoration: none;
                        color: $red;
                    }
                }
            }

            div:nth-child(2) {
                background: blue;
                display: flex;
                align-items: center;
                justify-content: space-around;
                flex: 3;
            }
        }
    }
</style>