require('dotenv').config();
if (!process.env.DISCORD_CLIENT_ID || !process.env.DISCORD_CLIENT_SECRET || !process.env.BOT_TOKEN) {
    console.error('❌ ERROR: Faltan variables de entorno requeridas en .env:');
    if (!process.env.DISCORD_CLIENT_ID) console.error('  - DISCORD_CLIENT_ID');
    if (!process.env.DISCORD_CLIENT_SECRET) console.error('  - DISCORD_CLIENT_SECRET');
    if (!process.env.BOT_TOKEN) console.error('  - BOT_TOKEN');
    process.exit(1);
}
const Discord = require('discord.js');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const cheerio = require('cheerio');
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const session = require('express-session');
const cookieParser = require('cookie-parser');

// Servidor Web
const app = express();
const server = http.createServer(app);
const io = socketIo(server, { cors: { origin: "*", methods: ["GET", "POST"] } });

// Configuración Passport
passport.use(new DiscordStrategy({
    clientID: process.env.DISCORD_CLIENT_ID,
    clientSecret: process.env.DISCORD_CLIENT_SECRET,
    callbackURL: process.env.NODE_ENV === 'production' 
        ? `${process.env.PRODUCTION_URL}/auth/discord/callback` 
        : 'http://localhost:3000/auth/discord/callback',
    scope: ['identify', 'guilds']
}, async (accessToken, refreshToken, profile, done) => {
    try {
        console.log('✅ Usuario autenticado desde Discord:', profile.username);
        
        // Asegurar que el usuario existe en la base de datos
        await initUser(profile.id, profile.username, profile.discriminator, profile.avatar);
        
        const userProfile = {
            id: profile.id,
            username: profile.username,
            discriminator: profile.discriminator,
            avatar: profile.avatar,
            accessToken: accessToken
        };
        
        return done(null, userProfile);
    } catch (error) {
        console.error('❌ Error en estrategia Discord:', error);
        return done(error, null);
    }
}));

passport.serializeUser((user, done) => {
    console.log('📦 Serializando usuario:', user.username);
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        console.log('📦 Deserializando usuario con ID:', id);
        
        // Asegurar que el usuario existe en userData
        if (!userData[id]) {
            console.log('⚠️ Usuario no encontrado en userData, inicializando...');
            await initUser(id);
        }
        
        const user = userData[id];
        if (user) {
            const userProfile = {
                id: id,
                username: user.username || 'Usuario',
                discriminator: user.discriminator || '0000',
                avatar: user.avatar,
                balance: user.balance || 1000,
                totalBets: user.totalBets || 0,
                wonBets: user.wonBets || 0,
                lostBets: user.lostBets || 0,
                totalWinnings: user.totalWinnings || 0
            };
            console.log('✅ Usuario deserializado correctamente:', userProfile.username);
            done(null, userProfile);
        } else {
            console.log('❌ Usuario no encontrado después de inicializar');
            done(null, null);
        }
    } catch (error) {
        console.error('❌ Error deserializando usuario:', error);
        done(error, null);
    }
});

// Middleware
app.use(cookieParser());
app.use(session({ 
    secret: process.env.SESSION_SECRET || 'tu_clave_secreta_muy_segura_aqui_123456', 
    resave: false, 
    saveUninitialized: false,
    cookie: { 
        maxAge: 24 * 60 * 60 * 1000, // 24 horas
        secure: false, // IMPORTANTE: Cambiar a false para desarrollo local
        httpOnly: true,
        sameSite: 'lax'
    },
    name: 'discord-auth-session' // Nombre específico para la sesión
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function requireAuth(req, res, next) { req.isAuthenticated() ? next() : res.status(401).json({ error: 'No autenticado' }); }

// Rutas Auth
app.get('/auth/discord', passport.authenticate('discord'));
app.get('/auth/discord/callback', 
    passport.authenticate('discord', { 
        failureRedirect: '/?error=auth_failed',
        failureMessage: true
    }), 
    async (req, res) => {
        try {
            console.log('🔄 Callback de Discord ejecutado');
            
            if (req.user) {
                console.log('✅ Usuario en callback:', req.user.username);
                
                // Asegurar que el usuario está correctamente inicializado
                await initUser(req.user.id, req.user.username, req.user.discriminator, req.user.avatar);
                
                console.log(`✅ Usuario autenticado exitosamente: ${req.user.username} - Balance: ${userData[req.user.id]?.balance || 1000}`);
                
                // Redireccionar al dashboard
                res.redirect('/dashboard');
            } else {
                console.log('❌ No hay usuario en req.user');
                res.redirect('/?error=no_user');
            }
        } catch (error) {
            console.error('❌ Error en callback:', error);
            res.redirect('/?error=callback_error');
        }
    }
);
app.get('/logout', (req, res) => {
    console.log('🚪 Usuario cerrando sesión:', req.user ? req.user.username : 'Desconocido');
    
    req.logout((err) => {
        if (err) {
            console.error('❌ Error al cerrar sesión:', err);
            return res.status(500).json({ error: 'Error al cerrar sesión' });
        }
        
        req.session.destroy((err) => {
            if (err) {
                console.error('❌ Error destruyendo sesión:', err);
            }
            res.clearCookie('discord-auth-session');
            res.redirect('/');
        });
    });
});

// API Routes
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/dashboard', requireAuth, (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/api/auth/status', async (req, res) => {
    try {
        console.log('🔍 Verificando estado de autenticación...');
        console.log('Session ID:', req.sessionID);
        console.log('Es autenticado:', req.isAuthenticated());
        console.log('Usuario en sesión:', req.user ? req.user.username : 'Ninguno');
        
        if (req.isAuthenticated() && req.user) {
            // Asegurar que el usuario existe en userData
            if (!userData[req.user.id]) {
                console.log('⚠️ Usuario autenticado pero no en userData, inicializando...');
                await initUser(req.user.id, req.user.username, req.user.discriminator, req.user.avatar);
            }
            
            const user = userData[req.user.id];
            
            const responseData = { 
                authenticated: true, 
                user: { 
                    id: req.user.id, 
                    username: user.username || req.user.username || 'Usuario', 
                    discriminator: user.discriminator || req.user.discriminator || '0000', 
                    avatar: user.avatar || req.user.avatar, 
                    balance: user.balance || 1000, 
                    totalBets: user.totalBets || 0, 
                    wonBets: user.wonBets || 0, 
                    lostBets: user.lostBets || 0, 
                    totalWinnings: user.totalWinnings || 0 
                } 
            };
            
            console.log('✅ Usuario autenticado:', responseData.user.username);
            res.json(responseData);
        } else {
            console.log('❌ Usuario no autenticado');
            res.json({ authenticated: false });
        }
    } catch (error) {
        console.error('❌ Error verificando estado:', error);
        res.json({ authenticated: false, error: error.message });
    }
});
app.get('/debug/session', (req, res) => {
    res.json({
        sessionID: req.sessionID,
        isAuthenticated: req.isAuthenticated(),
        user: req.user,
        session: req.session
    });
});

app.post('/api/bet', requireAuth, (req, res) => {
    const { matchId, prediction, amount } = req.body;
    const userId = req.user.id;
    if (!matches[matchId]) return res.status(400).json({ error: 'No existe un partido con ese ID' });
    if (matches[matchId].status !== 'upcoming') return res.status(400).json({ error: 'No puedes apostar en un partido que ya terminó' });
    if (!['team1', 'draw', 'team2'].includes(prediction)) return res.status(400).json({ error: 'Predicción inválida' });
    if (isNaN(amount) || amount <= 0) return res.status(400).json({ error: 'La cantidad debe ser un número mayor a 0' });
    if (userData[userId].balance < amount) return res.status(400).json({ error: 'No tienes suficiente dinero para esta apuesta' });
    
    const betId = Date.now().toString() + Math.random().toString(36).substr(2, 5);
    const odds = matches[matchId].odds[prediction];
    bets[betId] = { id: betId, userId, matchId, prediction, amount, odds, status: 'pending', timestamp: new Date().toISOString() };
    userData[userId].balance -= amount;
    userData[userId].totalBets++;
    if (!matches[matchId].bets) matches[matchId].bets = [];
    matches[matchId].bets.push(betId);
    saveData();
    broadcastUpdate('new-bet', { matchId, userId, amount });
    res.json({ success: true, bet: bets[betId], newBalance: userData[userId].balance });
});

app.get('/api/matches', (req, res) => res.json(Object.values(matches).filter(m => m.status === 'upcoming')));
app.get('/api/stats', (req, res) => res.json({ totalMatches: Object.values(matches).filter(m => m.status === 'upcoming').length, totalUsers: Object.keys(userData).length, totalBets: Object.keys(bets).length, totalVolume: Object.values(bets).reduce((sum, bet) => sum + bet.amount, 0) }));
app.get('/api/recent-bets', (req, res) => res.json(Object.values(bets).sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)).slice(0, 10).map(bet => { 
    const match = matches[bet.matchId]; 
    if (!match) return null; 
    
    let predictionText;
    
    // *** CORRECCIÓN PARA APUESTAS RECIENTES ***
    if (bet.betType === 'exact_score' && bet.exactScore) {
        predictionText = `Exacto ${bet.exactScore.home}-${bet.exactScore.away}`;
    } else if (bet.betType === 'special' && bet.description) {
        predictionText = bet.description;
    } else if (bet.betType === 'special_combined' && bet.description) {
        predictionText = bet.description;
    } else if (bet.prediction) {
        predictionText = bet.prediction === 'team1' ? match.team1.split(' (')[0] : 
                       bet.prediction === 'team2' ? match.team2.split(' (')[0] : 'Empate';
    } else if (bet.description) {
        predictionText = bet.description;
    } else {
        predictionText = 'Apuesta especial';
    }
    
    return { 
        match: `${match.team1.split(' (')[0]} vs ${match.team2.split(' (')[0]}`, 
        prediction: predictionText, 
        amount: bet.amount, 
        status: bet.status 
    }; 
}).filter(bet => bet !== null)));

app.get('/api/user/bets', requireAuth, (req, res) => {
    const userId = req.user.id;
    const userBets = Object.values(bets).filter(bet => bet.userId === userId).sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)).slice(0, 20).map(bet => {
        const match = matches[bet.matchId];
        if (!match) return null;
        
        let predictionText;
        
        // *** AQUÍ ESTÁ LA CORRECCIÓN PRINCIPAL ***
        if (bet.betType === 'exact_score' && bet.exactScore) {
            // Para resultado exacto, mostrar el marcador apostado
            predictionText = `Exacto ${bet.exactScore.home}-${bet.exactScore.away}`;
        } else if (bet.betType === 'special' && bet.description) {
            // Para apuestas especiales, usar la descripción guardada
            predictionText = bet.description;
        } else if (bet.betType === 'special_combined' && bet.description) {
            // Para apuestas especiales combinadas
            predictionText = bet.description;
        } else if (bet.prediction) {
            // Para apuestas simples tradicionales
            predictionText = bet.prediction === 'team1' ? match.team1.split(' (')[0] : 
                           bet.prediction === 'team2' ? match.team2.split(' (')[0] : 'Empate';
        } else if (bet.description) {
            // Fallback: usar descripción si existe
            predictionText = bet.description;
        } else {
            // Fallback final
            predictionText = 'Apuesta especial';
        }
        
        return { 
            ...bet, 
            match: { 
                team1: match.team1.split(' (')[0], 
                team2: match.team2.split(' (')[0], 
                result: match.result, 
                score: match.score 
            }, 
            predictionText, 
            potentialWinning: bet.amount * bet.odds 
        };
    }).filter(bet => bet !== null);
    res.json(userBets);
});

app.get('/api/user/stats', requireAuth, (req, res) => {
    const userId = req.user.id;
    const user = userData[userId];
    if (!user) { initUser(userId); return res.json(userData[userId]); }
    const winRate = user.totalBets > 0 ? (user.wonBets / user.totalBets * 100).toFixed(1) : 0;
    const profit = user.totalWinnings - (user.totalBets * 100);
    res.json({ ...user, winRate: parseFloat(winRate), profit, averageBet: user.totalBets > 0 ? (user.totalWinnings / user.totalBets).toFixed(2) : 0 });
});

io.on('connection', (socket) => {
    socket.emit('initial-data', { matches: Object.values(matches).filter(m => m.status === 'upcoming'), stats: { totalMatches: Object.values(matches).filter(m => m.status === 'upcoming').length, totalUsers: Object.keys(userData).length, totalBets: Object.keys(bets).length, totalVolume: Object.values(bets).reduce((sum, bet) => sum + bet.amount, 0) } });
});

function broadcastUpdate(type, data) { io.emit('update', { type, data }); }

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`🌐 Servidor web ejecutándose en http://localhost:${PORT}`));

// Agregar estas rutas después de las rutas API existentes en bot.js
app.get('/api/match/odds/:matchId', (req, res) => {
    const matchId = req.params.matchId;
    const match = matches[matchId];
    
    if (!match) {
        return res.status(404).json({ error: 'Partido no encontrado' });
    }
    
    // Cuotas básicas
    const basicOdds = match.odds;
    
    // Cuotas de resultado exacto
    const exactScores = {
        '0-0': calculateExactScoreOdds(match, { home: 0, away: 0 }),
        '1-0': calculateExactScoreOdds(match, { home: 1, away: 0 }),
        '0-1': calculateExactScoreOdds(match, { home: 0, away: 1 }),
        '1-1': calculateExactScoreOdds(match, { home: 1, away: 1 }),
        '2-0': calculateExactScoreOdds(match, { home: 2, away: 0 }),
        '0-2': calculateExactScoreOdds(match, { home: 0, away: 2 }),
        '2-1': calculateExactScoreOdds(match, { home: 2, away: 1 }),
        '1-2': calculateExactScoreOdds(match, { home: 1, away: 2 }),
        '2-2': calculateExactScoreOdds(match, { home: 2, away: 2 }),
        '3-0': calculateExactScoreOdds(match, { home: 3, away: 0 }),
        '0-3': calculateExactScoreOdds(match, { home: 0, away: 3 }),
        '3-1': calculateExactScoreOdds(match, { home: 3, away: 1 }),
        '1-3': calculateExactScoreOdds(match, { home: 1, away: 3 }),
        '3-2': calculateExactScoreOdds(match, { home: 3, away: 2 }),
        '2-3': calculateExactScoreOdds(match, { home: 2, away: 3 }),
        '3-3': calculateExactScoreOdds(match, { home: 3, away: 3 })
    };
    
    // Cuotas especiales
    const specialOdds = {
        'both_teams_score': calculateSpecialOdds(match, 'both_teams_score'),
        'total_goals_over_2_5': calculateSpecialOdds(match, 'total_goals_over_2_5'),
        'total_goals_under_2_5': calculateSpecialOdds(match, 'total_goals_under_2_5'),
        'home_goals_over_1_5': calculateSpecialOdds(match, 'home_goals_over_1_5'),
        'away_goals_over_1_5': calculateSpecialOdds(match, 'away_goals_over_1_5'),
        'corner_goal': calculateSpecialOdds(match, 'corner_goal'),
        'free_kick_goal': calculateSpecialOdds(match, 'free_kick_goal'),
        'bicycle_kick_goal': calculateSpecialOdds(match, 'bicycle_kick_goal'),
        'header_goal': calculateSpecialOdds(match, 'header_goal'),
        'striker_goal': calculateSpecialOdds(match, 'striker_goal'),
        'midfielder_goal': calculateSpecialOdds(match, 'midfielder_goal'),
        'defender_goal': calculateSpecialOdds(match, 'defender_goal'),
        'goalkeeper_goal': calculateSpecialOdds(match, 'goalkeeper_goal')
    };
    
    res.json({
        match: {
            id: match.id,
            team1: match.team1.split(' (')[0],
            team2: match.team2.split(' (')[0],
            matchTime: match.matchTime,
            status: match.status
        },
        basicOdds,
        exactScores,
        specialOdds
    });
});
app.post('/api/bet/special', requireAuth, (req, res) => {
    const { matchId, betType, amount, data } = req.body;
    const userId = req.user.id;
    
    if (!matches[matchId]) {
        return res.status(400).json({ error: 'No existe un partido con ese ID' });
    }
    
    if (matches[matchId].status !== 'upcoming') {
        return res.status(400).json({ error: 'No puedes apostar en un partido que ya terminó' });
    }
    
    if (isNaN(amount) || amount <= 0) {
        return res.status(400).json({ error: 'La cantidad debe ser un número mayor a 0' });
    }
    
    if (userData[userId].balance < amount) {
        return res.status(400).json({ error: 'No tienes suficiente dinero para esta apuesta' });
    }
    
    let betOdds, betDescription, betData;
    const match = matches[matchId];
    
    if (betType === 'exact_score') {
        const { home, away } = data;
        if (isNaN(home) || isNaN(away) || home < 0 || away < 0) {
            return res.status(400).json({ error: 'Resultado exacto inválido' });
        }
        
        betOdds = calculateExactScoreOdds(match, { home, away });
        betDescription = `Resultado exacto ${home}-${away}`;
        betData = { type: 'exact_score', exactScore: { home, away } };
    } else if (betType === 'special') {
    const specialType = data.specialType;
    const specialNames = {
        'both_teams_score': 'Ambos equipos marcan',
        'total_goals_over_2_5': 'Más de 2.5 goles',
        'total_goals_under_2_5': 'Menos de 2.5 goles',
        'home_goals_over_1_5': `Más de 1.5 goles ${match.team1.split(' (')[0]}`,
        'away_goals_over_1_5': `Más de 1.5 goles ${match.team2.split(' (')[0]}`,
        'corner_goal': 'Gol de córner',
        'free_kick_goal': 'Gol de tiro libre',
        'bicycle_kick_goal': 'Gol de chilena',
        'header_goal': 'Gol de cabeza',
        'striker_goal': 'Gol de delantero',
        'midfielder_goal': 'Gol de mediocampista',
        'defender_goal': 'Gol de defensa',
        'goalkeeper_goal': 'Gol de arquero'
    };
    
    if (!specialNames[specialType]) {
        return res.status(400).json({ error: 'Tipo de apuesta especial no válido' });
    }
    
    betOdds = calculateSpecialOdds(match, specialType);
    betDescription = specialNames[specialType];
    betData = { type: 'special', specialType };

} else if (betType === 'special_combined') {
    // AGREGAR este nuevo caso para apuestas especiales combinadas
    const specialBets = data.specialBets;
    
    if (!Array.isArray(specialBets) || specialBets.length === 0) {
        return res.status(400).json({ error: 'Debe incluir al menos una apuesta especial' });
    }
    
    const specialNames = {
        'both_teams_score': 'Ambos equipos marcan',
        'total_goals_over_2_5': 'Más de 2.5 goles',
        'total_goals_under_2_5': 'Menos de 2.5 goles',
        'home_goals_over_1_5': `Más de 1.5 goles ${match.team1.split(' (')[0]}`,
        'away_goals_over_1_5': `Más de 1.5 goles ${match.team2.split(' (')[0]}`,
        'corner_goal': 'Gol de córner',
        'free_kick_goal': 'Gol de tiro libre',
        'bicycle_kick_goal': 'Gol de chilena',
        'header_goal': 'Gol de cabeza',
        'striker_goal': 'Gol de delantero',
        'midfielder_goal': 'Gol de mediocampista',
        'defender_goal': 'Gol de defensa',
        'goalkeeper_goal': 'Gol de arquero'
    };
    
    // Validar todos los tipos especiales
    for (const specialType of specialBets) {
        if (!specialNames[specialType]) {
            return res.status(400).json({ error: `Tipo de apuesta especial no válido: ${specialType}` });
        }
    }
    
    // Calcular cuota combinada (multiplicar todas las cuotas)
    betOdds = specialBets.reduce((total, specialType) => {
        return total * calculateSpecialOdds(match, specialType);
    }, 1.0);
    
    // Crear descripción combinada
    betDescription = specialBets.map(type => specialNames[type]).join(' + ');
    betData = { 
        type: 'special_combined', 
        specialBets: specialBets.map(type => ({
            type,
            name: specialNames[type],
            odds: calculateSpecialOdds(match, type)
        }))
    };

} else {
    return res.status(400).json({ error: 'Tipo de apuesta no válido' });
}
    
    const betId = Date.now().toString() + Math.random().toString(36).substr(2, 5);
    
    bets[betId] = {
        id: betId,
        userId,
        matchId,
        amount,
        odds: betOdds,
        status: 'pending',
        timestamp: new Date().toISOString(),
        betType: betData.type,
        description: betDescription,
        ...betData
    };
    
    userData[userId].balance -= amount;
    userData[userId].totalBets++;
    
    if (!matches[matchId].bets) matches[matchId].bets = [];
    matches[matchId].bets.push(betId);
    
    saveData();
    broadcastUpdate('new-bet', { matchId, userId, amount });
    
    res.json({
        success: true,
        bet: {
            id: betId,
            description: betDescription,
            amount,
            odds: betOdds,
            potentialWinning: Math.round(amount * betOdds)
        },
        newBalance: userData[userId].balance
    });
});
// API para obtener partidos terminados con resultados
app.get('/api/finished-matches', (req, res) => {
    const finishedMatches = Object.values(matches)
        .filter(m => m.status === 'finished')
        .sort((a, b) => new Date(b.matchTime) - new Date(a.matchTime))
        .slice(0, 20)
        .map(match => ({
            id: match.id,
            team1: match.team1.split(' (')[0],
            team2: match.team2.split(' (')[0],
            result: match.result,
            score: match.score,
            matchTime: match.matchTime,
            isCustom: match.isCustom || false,
            isManual: matchResults[match.id]?.isManual || false
        }));
    
    res.json(finishedMatches);
});

// API para establecer resultado manual (solo para usuarios autenticados)
app.post('/api/set-result', requireAuth, (req, res) => {
    const { matchId, result, score1, score2 } = req.body;
    
    // Verificar que el usuario tiene permisos (puedes agregar verificación de admin aquí)
    const adminIds = ['438147217702780939']; // Mismo ID que en el bot
    if (!adminIds.includes(req.user.id)) {
        return res.status(403).json({ error: 'No tienes permisos para establecer resultados' });
    }
    
    const match = matches[matchId];
    if (!match) {
        return res.status(400).json({ error: 'No existe un partido con ese ID.' });
    }
    
    if (match.status !== 'upcoming') {
        return res.status(400).json({ error: 'Este partido ya tiene un resultado establecido.' });
    }
    
    if (!['team1', 'draw', 'team2'].includes(result)) {
        return res.status(400).json({ error: 'Resultado inválido. Usa: team1, draw, o team2.' });
    }
    
    const goals1 = parseInt(score1);
    const goals2 = parseInt(score2);
    
    if (isNaN(goals1) || isNaN(goals2) || goals1 < 0 || goals2 < 0) {
        return res.status(400).json({ error: 'El marcador debe ser números válidos (0 o mayor).' });
    }
    
    // Validar coherencia del resultado
    if (result === 'team1' && goals1 <= goals2) {
        return res.status(400).json({ error: 'El marcador no coincide con la victoria del equipo 1.' });
    }
    
    if (result === 'team2' && goals2 <= goals1) {
        return res.status(400).json({ error: 'El marcador no coincide con la victoria del equipo 2.' });
    }
    
    if (result === 'draw' && goals1 !== goals2) {
        return res.status(400).json({ error: 'Para empate, ambos equipos deben tener el mismo marcador.' });
    }
    
    // Establecer resultado
    match.status = 'finished';
    match.result = result;
    match.score = `${goals1}-${goals2}`;
    matchResults[matchId] = { 
        result, 
        score: `${goals1}-${goals2}`, 
        timestamp: new Date().toISOString(), 
        isManual: true,
        setBy: req.user.id
    };
    
    // Procesar apuestas
    processMatchBets(matchId, result);
    saveData();
    
    // Notificar a todos los clientes conectados
    broadcastUpdate('match-result', { matchId, result, score: `${goals1}-${goals2}`, isManual: true });
    
    res.json({ 
        success: true, 
        match: {
            id: match.id,
            team1: match.team1.split(' (')[0],
            team2: match.team2.split(' (')[0],
            result: match.result,
            score: match.score,
            isManual: true
        }
    });
});

// API para obtener partidos pendientes (para el selector de resultados)
app.get('/api/pending-matches', requireAuth, (req, res) => {
    // Solo permitir a admins
    const adminIds = ['438147217702780939'];
    if (!adminIds.includes(req.user.id)) {
        return res.status(403).json({ error: 'No tienes permisos para ver esta información' });
    }
    
    const pendingMatches = Object.values(matches)
        .filter(m => m.status === 'upcoming')
        .sort((a, b) => new Date(a.matchTime) - new Date(b.matchTime))
        .map(match => ({
            id: match.id,
            team1: match.team1.split(' (')[0],
            team2: match.team2.split(' (')[0],
            matchTime: match.matchTime,
            isCustom: match.isCustom || false,
            betsCount: match.bets ? match.bets.length : 0
        }));
    
    res.json(pendingMatches);
});

// Bot Discord
const client = new Discord.Client({ intents: [Discord.GatewayIntentBits.Guilds, Discord.GatewayIntentBits.GuildMessages, Discord.GatewayIntentBits.MessageContent] });

let userData = {}, teams = {}, matches = {}, bets = {}, matchResults = {};

function loadData() {
    try {
        if (fs.existsSync('userData.json')) userData = JSON.parse(fs.readFileSync('userData.json'));
        if (fs.existsSync('teams.json')) teams = JSON.parse(fs.readFileSync('teams.json'));
        if (fs.existsSync('matches.json')) matches = JSON.parse(fs.readFileSync('matches.json'));
        if (fs.existsSync('bets.json')) bets = JSON.parse(fs.readFileSync('bets.json'));
        if (fs.existsSync('matchResults.json')) matchResults = JSON.parse(fs.readFileSync('matchResults.json'));
    } catch (error) { console.log('Iniciando con datos vacíos:', error.message); }
}

function saveData() {
    fs.writeFileSync('userData.json', JSON.stringify(userData, null, 2));
    fs.writeFileSync('teams.json', JSON.stringify(teams, null, 2));
    fs.writeFileSync('matches.json', JSON.stringify(matches, null, 2));
    fs.writeFileSync('bets.json', JSON.stringify(bets, null, 2));
    fs.writeFileSync('matchResults.json', JSON.stringify(matchResults, null, 2));
}

function initUser(userId, username = null, discriminator = null, avatar = null) {
    return new Promise((resolve) => {
        let needsSave = false;
        
        console.log(`🔄 Inicializando usuario: ${userId} - ${username}`);
        
        if (!userData[userId]) {
            userData[userId] = { 
                balance: 1000, 
                totalBets: 0, 
                wonBets: 0, 
                lostBets: 0, 
                totalWinnings: 0, 
                username: username || 'Usuario',
                discriminator: discriminator || '0000',
                avatar: avatar || null
            };
            needsSave = true;
            console.log(`👤 Nuevo usuario creado: ${username || 'Usuario'} - Balance inicial: 1000`);
        } else {
            // Actualizar datos si ya existe el usuario pero con nueva info
            let updated = false;
            
            if (username && userData[userId].username !== username) {
                userData[userId].username = username;
                updated = true;
            }
            if (discriminator && userData[userId].discriminator !== discriminator) {
                userData[userId].discriminator = discriminator;
                updated = true;
            }
            if (avatar && userData[userId].avatar !== avatar) {
                userData[userId].avatar = avatar;
                updated = true;
            }
            
            if (updated) {
                needsSave = true;
                console.log(`🔄 Usuario actualizado: ${username || userData[userId].username}`);
            }
        }
        
        if (needsSave) {
            saveData();
        }
        
        resolve(userData[userId]);
    });
}

function calculateOdds(team1, team2) {
    const t1 = teams[team1], t2 = teams[team2];
    if (!t1 || !t2) return { team1: 2.0, draw: 3.0, team2: 2.0 };
    
    const t1League = t1.league || (team1.includes('(D1)') ? 'D1' : 'D2');
    const t2League = t2.league || (team2.includes('(D2)') ? 'D2' : 'D1');
    const t1Position = t1.position || 10, t2Position = t2.position || 10;
    
    let t1Strength = calculateTeamStrength(t1, t1League);
    let t2Strength = calculateTeamStrength(t2, t2League);
    
    // NUEVO: Penalizar fuertemente a los primeros puestos contra equipos de su liga
    if (t1League === t2League) {
        // Si es el primer puesto, paga muy poco contra cualquiera de su liga
        if (t1Position === 1) t1Strength *= 2.5;
        if (t2Position === 1) t2Strength *= 2.5;
        
        // Top 3 también recibe bonus considerable
        if (t1Position <= 3 && t1Position !== 1) t1Strength *= 1.8;
        if (t2Position <= 3 && t2Position !== 1) t2Strength *= 1.8;
    }
    
    if (t1League === 'D1' && t2League === 'D2') {
        const factor = calculateInterLeagueFactor(t1Position, t2Position, 'D1_vs_D2');
        t1Strength *= factor.team1Multiplier;
        t2Strength *= factor.team2Multiplier;
    } else if (t1League === 'D2' && t2League === 'D1') {
        const factor = calculateInterLeagueFactor(t2Position, t1Position, 'D2_vs_D1');
        t1Strength *= factor.team2Multiplier;
        t2Strength *= factor.team1Multiplier;
    }
    
    const total = t1Strength + t2Strength;
    let t1Prob = t1Strength / total, t2Prob = t2Strength / total;
    let drawProb = t1League !== t2League ? (((t1Position + t2Position) / 2) <= 5 ? 0.15 : ((t1Position + t2Position) / 2) <= 15 ? 0.12 : 0.08) : 0.22;
    
    const adjustedT1Prob = t1Prob * (1 - drawProb), adjustedT2Prob = t2Prob * (1 - drawProb);
    const margin = 0.05;
    
    let team1Odds = Math.max(1.02, Math.min(50.0, (1 / adjustedT1Prob) * (1 - margin)));
    let team2Odds = Math.max(1.02, Math.min(50.0, (1 / adjustedT2Prob) * (1 - margin)));
    let drawOdds = Math.max(2.8, Math.min(15.0, (1 / drawProb) * (1 - margin)));
    
    if (t1League !== t2League) {
        const oddsAdj = calculateSpecificOddsAdjustment(t1Position, t2Position, t1League, t2League);
        team1Odds = oddsAdj.team1Odds;
        team2Odds = oddsAdj.team2Odds;
        drawOdds = Math.max(4.0, Math.min(12.0, drawOdds));
    }
    
    return { team1: Math.round(team1Odds * 100) / 100, draw: Math.round(drawOdds * 100) / 100, team2: Math.round(team2Odds * 100) / 100 };
}
// Función para calcular cuotas de resultado exacto
function calculateExactScoreOdds(match, exactScore) {
    const t1 = teams[match.team1];
    const t2 = teams[match.team2];
    const { home, away } = exactScore;
    
    // Cuotas base según el resultado
    let baseOdds;
    if (home === away) {
        // Empates
        if (home === 0) baseOdds = 8.5; // 0-0
        else if (home === 1) baseOdds = 6.5; // 1-1
        else if (home === 2) baseOdds = 12.0; // 2-2
        else baseOdds = 25.0; // 3-3 o más
    } else if (Math.abs(home - away) === 1) {
        // Diferencia de 1 gol
        if (Math.max(home, away) <= 2) baseOdds = 5.5; // 1-0, 2-1
        else baseOdds = 9.0; // 3-2, etc.
    } else if (Math.abs(home - away) === 2) {
        // Diferencia de 2 goles
        if (Math.max(home, away) <= 3) baseOdds = 7.5; // 2-0, 3-1
        else baseOdds = 15.0; // 4-2, etc.
    } else {
        // Diferencia de 3+ goles
        baseOdds = 20.0 + (Math.abs(home - away) * 8);
    }
    
    // Ajustar según fuerza de equipos
    if (t1 && t2) {
        const strengthDiff = Math.abs((t1.position || 10) - (t2.position || 10));
        if (strengthDiff > 10) baseOdds *= 0.8; // Más probable si hay gran diferencia
        else if (strengthDiff < 3) baseOdds *= 1.3; // Menos probable si son parejos
    }
    
    return Math.max(4.0, Math.min(80.0, Math.round(baseOdds * 100) / 100));
}

// Función para calcular cuotas especiales
function calculateSpecialOdds(match, specialType, value = null) {
    const specialOdds = {
        'both_teams_score': 1.10,
        'total_goals_over_2_5': 1.35,
        'total_goals_under_2_5': 2.25,
        'home_goals_over_1_5': 1.25,
        'away_goals_over_1_5': 1.25,
        'corner_goal': 8.5,
        'free_kick_goal': 6.0,
        'bicycle_kick_goal': 35.0,
        'header_goal': 3.2,
        'striker_goal': 1.6,
        'midfielder_goal': 2.8,
        'defender_goal': 6.5,
        'goalkeeper_goal': 75.0
    };
    
    const t1 = teams[match.team1];
    const t2 = teams[match.team2];
    
    // Ajustar según características de los equipos
    let odds = specialOdds[specialType] || 5.0;
    
    if (t1 && t2) {
        const avgPosition = ((t1.position || 10) + (t2.position || 10)) / 2;
        
        // Equipos mejores tienden a hacer más goles especiales
        if (avgPosition <= 5) {
            if (['corner_goal', 'free_kick_goal', 'header_goal'].includes(specialType)) {
                odds *= 0.85;
            }
        } else if (avgPosition >= 15) {
            odds *= 1.15;
        }
        
        // Forma reciente afecta probabilidades
        const t1Form = (t1.lastFiveMatches || 'DDDDD').split('').filter(r => r === 'W').length;
        const t2Form = (t2.lastFiveMatches || 'DDDDD').split('').filter(r => r === 'W').length;
        const avgForm = (t1Form + t2Form) / 2;
        
        if (avgForm >= 4) odds *= 0.9; // Equipos en buena forma
        else if (avgForm <= 1) odds *= 1.1; // Equipos en mala forma
    }
    
    return Math.max(1.1, Math.min(100.0, Math.round(odds * 100) / 100));
}
function calculateInterLeagueFactor(d1Position, d2Position, matchType) {
    const normalizedD1 = Math.min(20, Math.max(1, d1Position)), normalizedD2 = Math.min(20, Math.max(1, d2Position));
    const d1Quality = (21 - normalizedD1) / 20, d2Quality = (21 - normalizedD2) / 20;
    let team1Multiplier, team2Multiplier;
    
    if (matchType === 'D1_vs_D2') {
        const qualityGap = d1Quality - d2Quality + 0.3;
        team1Multiplier = 1.0 + Math.max(0.2, qualityGap * 2);
        team2Multiplier = Math.max(0.3, 1.0 - qualityGap * 1.5);
    } else {
        const qualityGap = d1Quality - d2Quality + 0.3;
        team1Multiplier = Math.max(0.3, 1.0 - qualityGap * 1.5);
        team2Multiplier = 1.0 + Math.max(0.2, qualityGap * 2);
    }
    
    return { team1Multiplier, team2Multiplier };
}

function calculateSpecificOddsAdjustment(pos1, pos2, league1, league2) {
    let d1Position, d2Position, d1IsTeam1;
    
    if (league1 === 'D1') { d1Position = pos1; d2Position = pos2; d1IsTeam1 = true; }
    else { d1Position = pos2; d2Position = pos1; d1IsTeam1 = false; }
    
    const d1Quality = (21 - d1Position) / 20, d2Quality = (21 - d2Position) / 20;
    let d1Odds, d2Odds;
    
    if (d1Quality >= 0.9 && d2Quality <= 0.2) { d1Odds = 1.05; d2Odds = 15.0; }
    else if (d1Quality >= 0.8 && d2Quality <= 0.4) { d1Odds = 1.15; d2Odds = 8.0; }
    else if (d1Quality >= 0.6 && d2Quality <= 0.6) { d1Odds = 1.35; d2Odds = 5.5; }
    else if (d1Quality >= 0.4 && d2Quality >= 0.6) { d1Odds = 1.65; d2Odds = 3.8; }
    else if (d1Quality <= 0.2 && d2Quality >= 0.9) { d1Odds = 1.95; d2Odds = 4.30; }
    else {
        const qualityDiff = d1Quality - d2Quality + 0.2;
        d1Odds = Math.max(1.05, 2.0 - qualityDiff * 1.2);
        d2Odds = Math.max(2.5, 3.0 + qualityDiff * 4);
    }
    
    d1Odds = Math.max(1.02, Math.min(3.0, d1Odds));
    d2Odds = Math.max(2.0, Math.min(20.0, d2Odds));
    
    return d1IsTeam1 ? { team1Odds: d1Odds, team2Odds: d2Odds } : { team1Odds: d2Odds, team2Odds: d1Odds };
}

function calculateTeamStrength(team, league) {
    let strength = 50;
    if (league === 'D1') strength += 25;
    else if (league === 'D2') strength += 5;
    
    const position = team.position || 10;
    if (position === 1) strength += 35;
    else if (position <= 3) strength += 25;
    else if (position <= 6) strength += 15;
    else if (position <= 10) strength += 5;
    else if (position <= 15) strength -= 10;
    else strength -= 20;
    
    const recentForm = team.lastFiveMatches || 'DDDDD';
    let formPoints = 0, consecutiveWins = 0, consecutiveLosses = 0;
    
    for (let i = 0; i < recentForm.length; i++) {
        const result = recentForm[i];
        if (result === 'W') { formPoints += 3; consecutiveWins++; consecutiveLosses = 0; }
        else if (result === 'D') { formPoints += 1; consecutiveWins = 0; consecutiveLosses = 0; }
        else if (result === 'L') { formPoints += 0; consecutiveWins = 0; consecutiveLosses++; }
    }
    
    if (formPoints >= 13) strength += 20;
    else if (formPoints >= 10) strength += 15;
    else if (formPoints >= 7) strength += 5;
    else if (formPoints >= 4) strength -= 10;
    else strength -= 20;
    
    if (consecutiveWins >= 3) strength += 15;
    else if (consecutiveWins >= 2) strength += 8;
    if (consecutiveLosses >= 3) strength -= 15;
    else if (consecutiveLosses >= 2) strength -= 8;
    
    if (!recentForm.includes('L')) strength += 12;
    if (!recentForm.includes('W')) strength -= 15;
    
    return Math.max(15, Math.min(150, strength));
}

const LEAGUE_URLS = {
    d1: 'https://iosoccer-sa.com/torneos/d1',
    d2: 'https://iosoccer-sa.com/torneos/d2',
    d3: 'https://iosoccer-sa.com/torneos/d3',
    maradei: 'https://iosoccer-sa.com/torneos/maradei',
    cv: 'https://iosoccer-sa.com/torneos/cv',
    cd2: 'https://iosoccer-sa.com/torneos/cd2',
    cd3: 'https://iosoccer-sa.com/torneos/cd3',
    izoro: 'https://iosoccer-sa.com/torneos/izoro',
    izplata: 'https://iosoccer-sa.com/torneos/izplata'
};
// Mapeo de códigos a nombres completos
const TOURNAMENT_NAMES = {
    d1: 'Liga D1',
    d2: 'Liga D2',
    d3: 'Liga D3',
    maradei: 'Copa Maradei',
    cv: 'Copa ValencARc',
    cd2: 'Copa D2',
    cd3: 'Copa D3',
    izoro: 'Copa Intrazonal de Oro',
    izplata: 'Copa Intrazonal de Plata'
};

// Torneos que no tienen WDL (fase eliminatoria)
const KNOCKOUT_TOURNAMENTS = ['cv', 'izoro', 'izplata', 'cd2', 'cd3'];
async function scrapeIOSoccerTeams(league = 'd1') {
    try {
        const url = LEAGUE_URLS[league];
        if (!url) throw new Error(`Liga "${league}" no encontrada. Usa: ${Object.keys(LEAGUE_URLS).join(', ')}`);
        
        const response = await axios.get(url, { 
            headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' }, 
            timeout: 15000 
        });
        const $ = cheerio.load(response.data);
        const scrapedTeams = {};
        
        $('tbody tr').each((index, element) => {
            try {
                const $row = $(element);
                const positionText = $row.find('td:first-child span').text().trim();
                const position = parseInt(positionText);
                const teamName = $row.find('div.hidden.sm\\:block').text().trim();
                
                let lastFiveMatches = 'DDDDD'; // Default para torneos knockout
                
                // Solo buscar WDL si no es torneo eliminatorio
                if (!KNOCKOUT_TOURNAMENTS.includes(league)) {
                    const lastColumn = $row.find('td:last-child');
                    let tempMatches = '';
                    
                    lastColumn.find('div[style*="color"]').each((i, matchDiv) => {
                        if (tempMatches.length >= 5) return;
                        const style = $(matchDiv).attr('style') || '';
                        const text = $(matchDiv).text().trim();
                        if (style.includes('color: green') || text === 'W') tempMatches += 'W';
                        else if (style.includes('color: red') || text === 'L') tempMatches += 'L';
                        else tempMatches += 'D';
                    });
                    
                    if (tempMatches.length > 0) {
                        lastFiveMatches = tempMatches.padEnd(5, 'D').substring(0, 5);
                    }
                }
                
                if (teamName && !isNaN(position) && position > 0) {
                    scrapedTeams[`${teamName} (${league.toUpperCase()})`] = { 
                        position, 
                        lastFiveMatches, 
                        league: league.toUpperCase(), 
                        tournament: TOURNAMENT_NAMES[league],
                        originalName: teamName 
                    };
                }
            } catch (error) { 
                console.log(`⚠️ Error procesando fila ${index} en ${league}:`, error.message); 
            }
        });
        
        return scrapedTeams;
    } catch (error) { 
        console.error(`❌ Error obteniendo datos de ${league} (${TOURNAMENT_NAMES[league]}):`, error.message); 
        return null; 
    }
}

async function scrapeAllLeagues() {
    const allTeams = {};
    const tournaments = Object.keys(LEAGUE_URLS);
    
    try {
        for (let i = 0; i < tournaments.length; i++) {
            const tournament = tournaments[i];
            console.log(`🔍 Obteniendo datos de ${TOURNAMENT_NAMES[tournament]}...`);
            
            const tournamentTeams = await scrapeIOSoccerTeams(tournament);
            if (tournamentTeams) {
                Object.assign(allTeams, tournamentTeams);
                console.log(`✅ ${TOURNAMENT_NAMES[tournament]}: ${Object.keys(tournamentTeams).length} equipos`);
            }
            
            // Pausa entre requests para no sobrecargar el servidor
            if (i < tournaments.length - 1) {
                await new Promise(resolve => setTimeout(resolve, 2000));
            }
        }
        return allTeams;
    } catch (error) { 
        console.error('❌ Error obteniendo todas las ligas:', error.message); 
        return allTeams; 
    }
}

function createCustomMatch(team1Name, team2Name, tournament = null) {
    const team1 = findTeamByName(team1Name, tournament);
    const team2 = findTeamByName(team2Name, tournament);
    
    if (!team1) {
        let message = `No se encontró el equipo "${team1Name}".`;
        if (tournament) {
            message += ` en ${TOURNAMENT_NAMES[tournament] || tournament}.`;
        }
        message += ` Usa \`!equipos\` para ver la lista completa.`;
        return { success: false, message };
    }
    
    if (!team2) {
        let message = `No se encontró el equipo "${team2Name}".`;
        if (tournament) {
            message += ` en ${TOURNAMENT_NAMES[tournament] || tournament}.`;
        }
        message += ` Usa \`!equipos\` para ver la lista completa.`;
        return { success: false, message };
    }
    
    if (team1.fullName === team2.fullName) {
        return { success: false, message: 'Un equipo no puede jugar contra sí mismo.' };
    }
    
    const matchId = Date.now().toString();
    const odds = calculateOdds(team1.fullName, team2.fullName);
    const matchTime = new Date(Date.now() + Math.random() * 24 * 60 * 60 * 1000);
    
    matches[matchId] = { 
        id: matchId, 
        team1: team1.fullName, 
        team2: team2.fullName, 
        odds, 
        matchTime: matchTime.toISOString(), 
        status: 'upcoming', 
        bets: [], 
        isCustom: true,
        tournament: tournament || 'custom'
    };
    saveData();
    
    return { 
        success: true, 
        matchId, 
        match: matches[matchId], 
        team1Data: team1, 
        team2Data: team2,
        tournament: tournament 
    };
}

function findTeamByName(searchName, tournament = null) {
    if (!searchName) return null;
    const search = searchName.toLowerCase().trim();
    let teamEntries = Object.entries(teams);
    
    // Si se especifica torneo, filtrar por él
    if (tournament) {
        teamEntries = teamEntries.filter(([fullName, data]) => 
            data.league === tournament.toUpperCase() || 
            fullName.toLowerCase().includes(`(${tournament.toLowerCase()})`)
        );
    }
    
    // Búsqueda exacta
    for (const [fullName, data] of teamEntries) {
        if (fullName.toLowerCase() === search) return { fullName, data };
    }
    
    // Búsqueda sin paréntesis
    for (const [fullName, data] of teamEntries) {
        const nameWithoutParens = fullName.replace(/ \([^)]+\)/, '').toLowerCase();
        if (nameWithoutParens === search) return { fullName, data };
    }
    
    // Búsqueda parcial
    for (const [fullName, data] of teamEntries) {
        const nameWithoutParens = fullName.replace(/ \([^)]+\)/, '').toLowerCase();
        if (nameWithoutParens.includes(search) || search.includes(nameWithoutParens)) {
            return { fullName, data };
        }
    }
    
    // Búsqueda por palabras
    const searchWords = search.split(' ');
    for (const [fullName, data] of teamEntries) {
        const nameWords = fullName.toLowerCase().replace(/ \([^)]+\)/, '').split(' ');
        if (searchWords.every(word => nameWords.some(nameWord => 
            nameWord.includes(word) || word.includes(nameWord)
        ))) {
            return { fullName, data };
        }
    }
    
    return null;
}

function getTeamEmoji(teamName) { return ''; }

function giveMoney(fromUserId, toUserId, amount, isAdmin = false) {
    initUser(fromUserId); initUser(toUserId);
    if (isNaN(amount) || amount <= 0) return { success: false, message: 'La cantidad debe ser un número mayor a 0.' };
    if (!isAdmin) {
        if (userData[fromUserId].balance < amount) return { success: false, message: 'No tienes suficiente dinero para dar esa cantidad.' };
        userData[fromUserId].balance -= amount;
    }
    userData[toUserId].balance += amount;
    saveData();
    return { success: true, fromBalance: userData[fromUserId].balance, toBalance: userData[toUserId].balance, amount };
}

function getTeamSuggestions(searchName, limit = 5, tournament = null) {
    if (!searchName) return [];
    const search = searchName.toLowerCase().trim();
    const suggestions = [];
    
    let teamEntries = Object.entries(teams);
    
    // Filtrar por torneo si se especifica
    if (tournament) {
        teamEntries = teamEntries.filter(([fullName, data]) => 
            data.league === tournament.toUpperCase() || 
            fullName.toLowerCase().includes(`(${tournament.toLowerCase()})`)
        );
    }
    
    for (const [fullName, data] of teamEntries) {
        const nameWithoutLeague = fullName.replace(/ \([^)]+\)/, '');
        const score = calculateSimilarity(search, nameWithoutLeague.toLowerCase());
        if (score > 0.3) {
            suggestions.push({ 
                name: nameWithoutLeague, 
                fullName, 
                score, 
                league: data.league || 'CUSTOM',
                tournament: data.tournament || TOURNAMENT_NAMES[data.league?.toLowerCase()] || 'Custom',
                position: data.position 
            });
        }
    }
    
    return suggestions.sort((a, b) => b.score - a.score).slice(0, limit);
}

function calculateSimilarity(str1, str2) {
    const longer = str1.length > str2.length ? str1 : str2;
    const shorter = str1.length > str2.length ? str2 : str1;
    if (longer.length === 0) return 1.0;
    const matches = shorter.split('').filter((char, index) => longer.includes(char)).length;
    return matches / longer.length;
}

function generateRandomMatches() {
    const teamNames = Object.keys(teams);
    if (teamNames.length < 2) return;
    
    const matchId = Date.now().toString();
    const team1 = teamNames[Math.floor(Math.random() * teamNames.length)];
    let team2 = teamNames[Math.floor(Math.random() * teamNames.length)];
    while (team2 === team1) team2 = teamNames[Math.floor(Math.random() * teamNames.length)];
    
    const odds = calculateOdds(team1, team2);
    const matchTime = new Date(Date.now() + Math.random() * 24 * 60 * 60 * 1000);
    
    matches[matchId] = { id: matchId, team1, team2, odds, matchTime: matchTime.toISOString(), status: 'upcoming', bets: [] };
    saveData();
    broadcastUpdate('new-match', matches[matchId]);
    return matchId;
}

function simulateMatch(matchId) {
    const match = matches[matchId];
    if (!match || match.status !== 'upcoming') return null;
    
    const t1 = teams[match.team1], t2 = teams[match.team2];
    if (!t1 || !t2) return null;
    
    const t1League = t1.league || (match.team1.includes('(D1)') ? 'D1' : 'D2');
    const t2League = t2.league || (match.team2.includes('(D2)') ? 'D2' : 'D1');
    
    let t1Strength = calculateTeamStrength(t1, t1League);
    let t2Strength = calculateTeamStrength(t2, t2League);
    
    if (t1League === 'D1' && t2League === 'D2') {
        const positionFactor = calculateInterLeagueFactor(t1.position, t2.position, 'D1_vs_D2');
        t1Strength *= positionFactor.team1Multiplier;
        t2Strength *= positionFactor.team2Multiplier;
    } else if (t1League === 'D2' && t2League === 'D1') {
        const positionFactor = calculateInterLeagueFactor(t2.position, t1.position, 'D2_vs_D1');
        t1Strength *= positionFactor.team2Multiplier;
        t2Strength *= positionFactor.team1Multiplier;
    }
    
    const total = t1Strength + t2Strength;
    const t1Prob = t1Strength / total;
    
    let drawProb = t1League !== t2League ? (((t1.position + t2.position) / 2) <= 5 ? 0.15 : ((t1.position + t2.position) / 2) <= 15 ? 0.12 : 0.08) : 0.22;
    
    const random = Math.random();
    let result = random < t1Prob * (1 - drawProb) ? 'team1' : random < (1 - drawProb) ? 'team2' : 'draw';
    
    let score1, score2;
    if (result === 'team1') {
        if (t1League === 'D1' && t2League === 'D2') { score1 = Math.floor(Math.random() * 4) + 2; score2 = Math.floor(Math.random() * 2); }
        else { score1 = Math.floor(Math.random() * 3) + 1; score2 = Math.floor(Math.random() * score1); }
    } else if (result === 'team2') {
        if (t2League === 'D1' && t1League === 'D2') { score2 = Math.floor(Math.random() * 4) + 2; score1 = Math.floor(Math.random() * 2); }
        else { score2 = Math.floor(Math.random() * 3) + 1; score1 = Math.floor(Math.random() * score2); }
    } else { score1 = score2 = Math.floor(Math.random() * 3); }
    
    match.status = 'finished';
    match.result = result;
    match.score = `${score1}-${score2}`;
    matchResults[matchId] = { result, score: `${score1}-${score2}`, timestamp: new Date().toISOString() };
    processMatchBets(matchId, result);
    saveData();
    broadcastUpdate('match-result', { matchId, result, score: `${score1}-${score2}` });
    return { result, score: `${score1}-${score2}` };
}

function setManualResult(matchId, result, score1, score2, specialResults = {}) {
    const match = matches[matchId];
    if (!match) return { success: false, message: 'No existe un partido con ese ID.' };
    if (match.status !== 'upcoming') return { success: false, message: 'Este partido ya tiene un resultado establecido.' };
    if (!['team1', 'draw', 'team2'].includes(result)) return { success: false, message: 'Resultado inválido. Usa: team1, draw, o team2.' };
    if (isNaN(score1) || isNaN(score2) || score1 < 0 || score2 < 0) return { success: false, message: 'El marcador debe ser números válidos (0 o mayor).' };
    if (result === 'team1' && score1 <= score2) return { success: false, message: 'El marcador no coincide con la victoria del equipo 1.' };
    if (result === 'team2' && score2 <= score1) return { success: false, message: 'El marcador no coincide con la victoria del equipo 2.' };
    if (result === 'draw' && score1 !== score2) return { success: false, message: 'Para empate, ambos equipos deben tener el mismo marcador.' };
    
    match.status = 'finished';
    match.result = result;
    match.score = `${score1}-${score2}`;
    matchResults[matchId] = { 
        result, 
        score: `${score1}-${score2}`, 
        timestamp: new Date().toISOString(), 
        isManual: true,
        specialResults 
    };
    
    processMatchBets(matchId, result, score1, score2, specialResults);
    saveData();
    return { success: true, match, result, score: `${score1}-${score2}` };
}

function processMatchBets(matchId, result, goals1 = null, goals2 = null, specialResults = {}) {
    const match = matches[matchId];
    if (!match.bets) return;
    
    for (let betId of match.bets) {
        const bet = bets[betId];
        if (!bet) continue;
        
        let won = false;
        
        if (bet.betType === 'simple') {
            won = bet.prediction === result;
        } else if (bet.betType === 'exact_score' && goals1 !== null && goals2 !== null) {
            won = bet.exactScore.home === goals1 && bet.exactScore.away === goals2;
        } else if (bet.betType === 'special' && specialResults) {
            won = checkSpecialBets([{ specialType: bet.specialType }], goals1, goals2, specialResults);
        } else if (bet.betType === 'special_combined' && specialResults) {
            won = checkSpecialBets(bet.specialBets, goals1, goals2, specialResults);
        } else if (bet.betType === 'combined') {
            won = checkCombinedBets(bet.combinedBets, result, goals1, goals2, specialResults);
        } else {
            // Fallback para apuestas simples sin tipo específico
            won = bet.prediction === result;
        }
        
        bet.status = won ? 'won' : 'lost';
        bet.result = result;
        
        if (won) {
            const winnings = bet.amount * bet.odds;
            userData[bet.userId].balance += winnings;
            userData[bet.userId].wonBets++;
            userData[bet.userId].totalWinnings += winnings;
        } else {
            userData[bet.userId].lostBets++;
        }
    }
}

function checkSpecialBets(specialBets, goals1, goals2, specialResults) {
    for (const specialBet of specialBets) {
        const { type } = specialBet;
        let betWon = false;
        
        switch (type) {
            case 'both_teams_score':
                betWon = goals1 > 0 && goals2 > 0;
                break;
            case 'total_goals_over_2_5':
                betWon = (goals1 + goals2) > 2.5;
                break;
            case 'total_goals_under_2_5':
                betWon = (goals1 + goals2) < 2.5;
                break;
            case 'home_goals_over_1_5':
                betWon = goals1 > 1.5;
                break;
            case 'away_goals_over_1_5':
                betWon = goals2 > 1.5;
                break;
            default:
                // Para goles especiales, usar specialResults
                betWon = specialResults[type] === true;
                break;
        }
        
        if (!betWon) return false; // Si falla una, falla toda la apuesta
    }
    return true;
}

function checkCombinedBets(combinedBets, result, goals1, goals2, specialResults) {
    // Para apuestas combinadas, TODAS deben ganar
    for (const bet of combinedBets) {
        let betWon = false;
        
        if (bet.type === 'simple') {
            betWon = bet.prediction === result;
        } else if (bet.type === 'exact_score') {
            betWon = bet.score.home === goals1 && bet.score.away === goals2;
        } else if (bet.type === 'special') {
            betWon = checkSpecialBets([bet], goals1, goals2, specialResults);
        }
        
        if (!betWon) return false; // Si falla una, falla toda la combinada
    }
    return true;
}

function deleteMatch(matchId) {
    if (!matches[matchId]) return { success: false, message: 'No existe un partido con ese ID.' };
    const match = matches[matchId];
    if (match.status === 'finished') return { success: false, message: 'No se puede eliminar un partido que ya terminó.' };
    
    if (match.bets && match.bets.length > 0) {
        for (let betId of match.bets) {
            const bet = bets[betId];
            if (bet && bet.status === 'pending') {
                userData[bet.userId].balance += bet.amount;
                userData[bet.userId].totalBets--;
                delete bets[betId];
            }
        }
    }
    
    delete matches[matchId];
    saveData();
    return { success: true, message: `Partido eliminado correctamente. ${match.bets ? match.bets.length : 0} apuestas fueron canceladas y el dinero devuelto.`, match };
}

function deleteAllUpcomingMatches() {
    const upcomingMatches = Object.keys(matches).filter(id => matches[id].status === 'upcoming');
    if (upcomingMatches.length === 0) return { success: false, message: 'No hay partidos pendientes para eliminar.' };
    
    let totalBetsReturned = 0, totalMoneyReturned = 0;
    
    for (let matchId of upcomingMatches) {
        const match = matches[matchId];
        if (match.bets && match.bets.length > 0) {
            for (let betId of match.bets) {
                const bet = bets[betId];
                if (bet && bet.status === 'pending') {
                    userData[bet.userId].balance += bet.amount;
                    userData[bet.userId].totalBets--;
                    totalBetsReturned++;
                    totalMoneyReturned += bet.amount;
                    delete bets[betId];
                }
            }
        }
        delete matches[matchId];
    }
    
    saveData();
    return { success: true, message: `Se eliminaron ${upcomingMatches.length} partidos pendientes. ${totalBetsReturned} apuestas canceladas y ${totalMoneyReturned} devuelto a los usuarios.`, deletedCount: upcomingMatches.length, betsReturned: totalBetsReturned, moneyReturned: totalMoneyReturned };
}

function deleteFinishedMatches() {
    const finishedMatches = Object.keys(matches).filter(id => matches[id].status === 'finished');
    if (finishedMatches.length === 0) return { success: false, message: 'No hay partidos terminados para eliminar.' };
    
    for (let matchId of finishedMatches) {
        delete matches[matchId];
        if (matchResults[matchId]) delete matchResults[matchId];
    }
    
    saveData();
    return { success: true, message: `Se eliminaron ${finishedMatches.length} partidos terminados del historial.`, deletedCount: finishedMatches.length };
}

client.on('messageCreate', async (message) => {
    if (message.author.bot) return;
    
    const args = message.content.split(' ');
    const command = args[0].toLowerCase();
    
    initUser(message.author.id, message.author.username, message.author.discriminator, message.author.avatar);
    
    switch (command) {
case '!crearmatch':
case '!crearpartido':
case '!match':
    if (args.length < 3) {
        const tournamentsText = Object.entries(TOURNAMENT_NAMES)
            .map(([code, name]) => `• \`${code}\` - ${name}`)
            .join('\n');
        
        message.reply(`❌ Uso: \`!crearmatch <equipo1> vs <equipo2> [torneo]\`
**Ejemplos:**
\`!crearmatch "Boca" vs "River"\` (busca en todos los torneos)
\`!crearmatch "Boca" vs "River" d1\` (solo en Liga D1)

**Torneos disponibles:**
${tournamentsText}`);
        return;
    }
    
    const fullCommand = message.content.slice(command.length).trim();
    const vsIndex = fullCommand.toLowerCase().indexOf(' vs ');
    if (vsIndex === -1) {
        message.reply('❌ Formato incorrecto. Usa: `!crearmatch <equipo1> vs <equipo2> [torneo]`');
        return;
    }
    
    const team1Input = fullCommand.slice(0, vsIndex).trim().replace(/"/g, '');
    const restOfCommand = fullCommand.slice(vsIndex + 4).trim();
    
    // Buscar si hay torneo especificado al final
    let team2Input, selectedTournament = null;
    const possibleTournaments = Object.keys(TOURNAMENT_NAMES);
    const lastWord = restOfCommand.split(' ').pop().toLowerCase();
    
    if (possibleTournaments.includes(lastWord)) {
        selectedTournament = lastWord;
        team2Input = restOfCommand.slice(0, restOfCommand.lastIndexOf(' ')).trim().replace(/"/g, '');
    } else {
        team2Input = restOfCommand.replace(/"/g, '');
    }
    
    if (!team1Input || !team2Input) {
        message.reply('❌ Debes especificar ambos equipos.');
        return;
    }
    
    const customResult = createCustomMatch(team1Input, team2Input, selectedTournament);
    if (!customResult.success) {
        let suggestionText = customResult.message;
        
        if (customResult.message.includes('No se encontró el equipo')) {
            const failedTeam = customResult.message.includes(`"${team1Input}"`) ? team1Input : team2Input;
            const suggestions = getTeamSuggestions(failedTeam, 3, selectedTournament);
            if (suggestions.length > 0) {
                suggestionText += '\n\n**¿Quisiste decir?**\n' + 
                    suggestions.map(s => `• ${getTeamEmoji(s.fullName)} **${s.name}** (${s.tournament} - Pos. ${s.position})`).join('\n');
            }
        }
        message.reply(suggestionText);
        return;
    }
    
    const customMatch = customResult.match;
    const t1Data = customResult.team1Data;
    const t2Data = customResult.team2Data;
    const customT1League = t1Data.data.league || 'CUSTOM';
    const customT2League = t2Data.data.league || 'CUSTOM';
    
    let customAnalysisText;
    if (selectedTournament) {
        customAnalysisText = `🏆 **${TOURNAMENT_NAMES[selectedTournament]}**\nPos. ${t1Data.data.position || '?'} vs Pos. ${t2Data.data.position || '?'}`;
    } else if (customT1League !== customT2League) {
        customAnalysisText = `🔥 **Partido Inter-Liga**\n${t1Data.data.tournament || customT1League} vs ${t2Data.data.tournament || customT2League}`;
    } else {
        customAnalysisText = `📊 **${t1Data.data.tournament || customT1League}**\nPos. ${t1Data.data.position || '?'} vs Pos. ${t2Data.data.position || '?'}`;
    }
    
    const customMatchEmbed = new Discord.EmbedBuilder()
        .setColor('#9900ff')
        .setTitle('🎯 Partido Creado')
        .addFields(
            { name: 'ID del Partido', value: customResult.matchId, inline: false },
            { name: 'Equipos', value: `${getTeamEmoji(customMatch.team1)} **${customMatch.team1.split(' (')[0]}** vs **${customMatch.team2.split(' (')[0]}** ${getTeamEmoji(customMatch.team2)}`, inline: false },
            { name: 'Torneo', value: customAnalysisText, inline: false },
            { name: 'Cuotas', value: `**${customMatch.team1.split(' (')[0]}**: ${customMatch.odds.team1}\n**Empate**: ${customMatch.odds.draw}\n**${customMatch.team2.split(' (')[0]}**: ${customMatch.odds.team2}`, inline: false },
            { name: 'Forma Reciente', value: `${customMatch.team1.split(' (')[0]}: ${t1Data.data.lastFiveMatches || 'DDDDD'}\n${customMatch.team2.split(' (')[0]}: ${t2Data.data.lastFiveMatches || 'DDDDD'}`, inline: false },
            { name: 'Hora del partido', value: new Date(customMatch.matchTime).toLocaleString(), inline: false }
        )
        .setFooter({ text: 'Partido listo para apostar! Usa !apostar <ID> <team1/draw/team2> <cantidad>' });
    
    message.reply({ embeds: [customMatchEmbed] });
    break;
            
        case '!balance':
        case '!dinero':
            const user = userData[message.author.id];
            const embed = new Discord.EmbedBuilder()
                .setColor('#00ff00')
                .setTitle('💰 Tu Balance')
                .addFields(
                    { name: 'Dinero disponible', value: `${user.balance}`, inline: true },
                    { name: 'Apuestas totales', value: `${user.totalBets}`, inline: true },
                    { name: 'Apuestas ganadas', value: `${user.wonBets}`, inline: true },
                    { name: 'Apuestas perdidas', value: `${user.lostBets}`, inline: true },
                    { name: 'Ganancias totales', value: `${user.totalWinnings}`, inline: true },
                    { name: 'Tasa de éxito', value: `${user.totalBets > 0 ? Math.round((user.wonBets/user.totalBets)*100) : 0}%`, inline: true }
                );
            message.reply({ embeds: [embed] });
            break;
            
        case '!equipos':
case '!teams':
    if (Object.keys(teams).length === 0) {
        message.reply('❌ No hay equipos registrados. Usa `!actualizartodo` para obtener equipos de IOSoccer.');
        return;
    }
    
    // Agrupar equipos por torneo
    const teamsByTournament = {};
    Object.entries(teams).forEach(([name, data]) => {
        const tournament = data.tournament || TOURNAMENT_NAMES[data.league?.toLowerCase()] || 'Otros';
        if (!teamsByTournament[tournament]) {
            teamsByTournament[tournament] = [];
        }
        teamsByTournament[tournament].push([name, data]);
    });
    
    // Ordenar equipos dentro de cada torneo por posición
    Object.keys(teamsByTournament).forEach(tournament => {
        teamsByTournament[tournament].sort((a, b) => a[1].position - b[1].position);
    });
    
    // Crear texto organizado por torneos
    let teamText = '';
    const tournamentOrder = ['Liga D1', 'Liga D2', 'Liga D3', 'Copa Maradei', 'Copa ValencARc', 'Copa D2', 'Copa D3', 'Copa Intrazonal de Oro', 'Copa Intrazonal de Plata'];
    
    // Mostrar torneos en orden específico
    tournamentOrder.forEach(tournament => {
        if (teamsByTournament[tournament] && teamsByTournament[tournament].length > 0) {
            const isKnockout = ['Copa ValencARc', 'Copa Intrazonal de Oro', 'Copa Intrazonal de Plata', 'Copa D2', 'Copa D3'].includes(tournament);
            const emoji = tournament.includes('Liga') ? '🏆' : '🏅';
            
            teamText += `**${emoji} ${tournament}**\n`;
            teamText += teamsByTournament[tournament]
                .slice(0, 10) // Limitar a 10 equipos por torneo para no exceder límites
                .map(([name, data]) => {
                    const teamName = name.replace(/ \([^)]+\)/, '');
                    const formText = isKnockout ? '(Eliminatoria)' : `(${data.lastFiveMatches || 'DDDDD'})`;
                    return `${data.position}. ${getTeamEmoji(name)} **${teamName}** ${formText}`;
                }).join('\n');
            
            if (teamsByTournament[tournament].length > 10) {
                teamText += `\n... y ${teamsByTournament[tournament].length - 10} más`;
            }
            teamText += '\n\n';
        }
    });
    
    // Mostrar otros torneos no listados
    Object.keys(teamsByTournament).forEach(tournament => {
        if (!tournamentOrder.includes(tournament)) {
            teamText += `**🎯 ${tournament}**\n`;
            teamText += teamsByTournament[tournament]
                .slice(0, 5)
                .map(([name, data]) => `${data.position}. ${getTeamEmoji(name)} **${name.replace(/ \([^)]+\)/, '')}** (${data.lastFiveMatches || 'DDDDD'})`)
                .join('\n') + '\n\n';
        }
    });
    
    const teamsEmbed = new Discord.EmbedBuilder()
        .setColor('#0099ff')
        .setTitle('🏆 Equipos por Torneo | IOSoccer Sudamérica')
        .setDescription(teamText || 'No hay equipos registrados')
        .setFooter({ text: 'W=Victoria, D=Empate, L=Derrota | Usa !actualizartodo para actualizar' });
    
    message.reply({ embeds: [teamsEmbed] });
    break;
            
        case '!partidos':
        case '!matches':
            const upcomingMatches = Object.values(matches).filter(m => m.status === 'upcoming');
            if (upcomingMatches.length === 0) { message.reply('❌ No hay partidos próximos. Usa `!generarmatch` para crear partidos.'); return; }
            
            const matchesText = upcomingMatches.map(match => {
                const matchTime = new Date(match.matchTime);
                const t1 = teams[match.team1], t2 = teams[match.team2];
                const t1Emoji = getTeamEmoji(match.team1), t2Emoji = getTeamEmoji(match.team2);
                const t1League = t1?.league || (match.team1.includes('(D1)') ? 'D1' : 'D2');
                const t2League = t2?.league || (match.team2.includes('(D2)') ? 'D2' : 'D1');
                const t1Form = t1?.lastFiveMatches || 'DDDDD', t2Form = t2?.lastFiveMatches || 'DDDDD';
                const t1Position = t1?.position || '?', t2Position = t2?.position || '?';
                
                let matchAnalysis = t1League !== t2League ? `🔥 **INTER-LIGA** - D1 (pos.${t1League === 'D1' ? t1Position : t2Position}) vs D2 (pos.${t1League === 'D1' ? t2Position : t1Position})` : `📊 Intra-liga ${t1League} - Pos.${t1Position} vs Pos.${t2Position}`;
                const customIndicator = match.isCustom ? ' 🎯 **PERSONALIZADO**' : '';
                
                return `**ID: ${match.id}**${customIndicator}\n${t1Emoji} **${match.team1.split(' (')[0]}** vs **${match.team2.split(' (')[0]}** ${t2Emoji}\n${matchAnalysis}\n📅 ${matchTime.toLocaleString()}\n💰 **${match.team1.split(' (')[0]}** (${match.odds.team1}) | **Empate** (${match.odds.draw}) | **${match.team2.split(' (')[0]}** (${match.odds.team2})\n📈 Forma: ${t1Form} vs ${t2Form}\n`;
            }).join('\n');
            
            const matchesEmbed = new Discord.EmbedBuilder().setColor('#ff9900').setTitle('⚽ Próximos Partidos').setDescription(matchesText);
            message.reply({ embeds: [matchesEmbed] });
            break;
            
        case '!generarmatch':
            if (Object.keys(teams).length < 2) { message.reply('❌ Necesitas al menos 2 equipos para generar un partido.'); return; }
            
            const newMatchId = generateRandomMatches();
            const newMatch = matches[newMatchId];
            const newT1 = teams[newMatch.team1], newT2 = teams[newMatch.team2];
            const newT1League = newT1?.league || (newMatch.team1.includes('(D1)') ? 'D1' : 'D2');
            const newT2League = newT2?.league || (newMatch.team2.includes('(D2)') ? 'D2' : 'D1');
            
            let analysisText = newT1League !== newT2League ? `🔥 **Partido**\nD1 (posición ${newT1League === 'D1' ? (newT1?.position || '?') : (newT2?.position || '?')}) vs D2 (posición ${newT1League === 'D1' ? (newT2?.position || '?') : (newT1?.position || '?')})` : `📊 Partido ${newT1League}`;
            
            const newMatchEmbed = new Discord.EmbedBuilder()
                .setColor('#00ff00')
                .setTitle('✅ Nuevo Partido Generado')
                .addFields(
                    { name: 'ID del Partido', value: newMatchId, inline: false },
                    { name: 'Equipos', value: `${getTeamEmoji(newMatch.team1)} ${newMatch.team1.split(' (')[0]} vs ${newMatch.team2.split(' (')[0]} ${getTeamEmoji(newMatch.team2)}`, inline: false },
                    { name: 'Análisis', value: analysisText, inline: false },
                    { name: 'Cuotas', value: `${newMatch.team1.split(' (')[0]}: ${newMatch.odds.team1}\nEmpate: ${newMatch.odds.draw}\n${newMatch.team2.split(' (')[0]}: ${newMatch.odds.team2}`, inline: false },
                    { name: 'Hora del partido', value: new Date(newMatch.matchTime).toLocaleString(), inline: false }
                );
            message.reply({ embeds: [newMatchEmbed] });
            break;
            
        case '!apostar':
        case '!bet':
            if (args.length < 4) { message.reply('❌ Uso: `!apostar <ID_partido> <team1/draw/team2> <cantidad>`\nEjemplo: `!apostar 1234567890 team1 100`'); return; }
            
            const matchId = args[1], prediction = args[2].toLowerCase(), amount = parseFloat(args[3]);
            
            if (!matches[matchId]) { message.reply('❌ No existe un partido con ese ID.'); return; }
            if (matches[matchId].status !== 'upcoming') { message.reply('❌ No puedes apostar en un partido que ya terminó.'); return; }
            if (!['team1', 'draw', 'team2'].includes(prediction)) { message.reply('❌ Predicción inválida. Usa: team1, draw, o team2.'); return; }
            if (isNaN(amount) || amount <= 0) { message.reply('❌ La cantidad debe ser un número mayor a 0.'); return; }
            if (userData[message.author.id].balance < amount) { message.reply('❌ No tienes suficiente dinero para esta apuesta.'); return; }
            
            const betId = Date.now().toString() + Math.random().toString(36).substr(2, 5);
            const odds = matches[matchId].odds[prediction];
            
            bets[betId] = { id: betId, userId: message.author.id, matchId, prediction, amount, odds, status: 'pending', timestamp: new Date().toISOString() };
            userData[message.author.id].balance -= amount;
            userData[message.author.id].totalBets++;
            
            if (!matches[matchId].bets) matches[matchId].bets = [];
            matches[matchId].bets.push(betId);
            
            saveData();
            broadcastUpdate('new-bet', { matchId, userId: message.author.id, amount });
            
            const match = matches[matchId];
            let predictionText = prediction === 'team1' ? match.team1.split(' (')[0] : prediction === 'team2' ? match.team2.split(' (')[0] : 'Empate';
            
            const betEmbed = new Discord.EmbedBuilder()
                .setColor('#00ff00')
                .setTitle('✅ Apuesta Realizada')
                .addFields(
                    { name: 'Partido', value: `${match.team1.split(' (')[0]} vs ${match.team2.split(' (')[0]}`, inline: false },
                    { name: 'Tu predicción', value: predictionText, inline: true },
                    { name: 'Cantidad apostada', value: `${amount}`, inline: true },
                    { name: 'Cuota', value: odds.toString(), inline: true },
                    { name: 'Ganancia potencial', value: `${Math.round(amount * odds)}`, inline: true },
                    { name: 'Balance restante', value: `${userData[message.author.id].balance}`, inline: true }
                );
            message.reply({ embeds: [betEmbed] });
            break;
            
        case '!simular':
        case '!simulate':
            if (args.length < 2) { message.reply('❌ Uso: `!simular <ID_partido>`'); return; }
            
            const simMatchId = args[1];
            if (!matches[simMatchId]) { message.reply('❌ No existe un partido con ese ID.'); return; }
            if (matches[simMatchId].status !== 'upcoming') { message.reply('❌ Este partido ya fue simulado.'); return; }
            
            const result = simulateMatch(simMatchId);
            const simMatch = matches[simMatchId];
            
            let winnerText = result.result === 'team1' ? simMatch.team1.split(' (')[0] : result.result === 'team2' ? simMatch.team2.split(' (')[0] : 'Empate';
            
            const resultEmbed = new Discord.EmbedBuilder()
                .setColor('#ff0000')
                .setTitle('🏁 Resultado del Partido')
                .addFields(
                    { name: 'Partido', value: `${getTeamEmoji(simMatch.team1)} ${simMatch.team1.split(' (')[0]} vs ${simMatch.team2.split(' (')[0]} ${getTeamEmoji(simMatch.team2)}`, inline: false },
                    { name: 'Resultado', value: result.score, inline: true },
                    { name: 'Ganador', value: winnerText, inline: true }
                );
            message.reply({ embeds: [resultEmbed] });
            break;
            
        case '!dar':
        case '!give':
        case '!dardinero':
            if (args.length < 3) { message.reply('❌ Uso: `!dar <@usuario> <cantidad>`\nEjemplo: `!dar @amigo 500`'); return; }
            
            const mentionedUser = message.mentions.users.first();
            if (!mentionedUser) { message.reply('❌ Debes mencionar a un usuario válido. Ejemplo: `!dar @amigo 500`'); return; }
            if (mentionedUser.id === message.author.id) { message.reply('❌ No puedes darte dinero a ti mismo.'); return; }
            if (mentionedUser.bot) { message.reply('❌ No puedes dar dinero a un bot.'); return; }
            
            const amountToGive = parseFloat(args[2]);
            const giveResult = giveMoney(message.author.id, mentionedUser.id, amountToGive, false);
            
            if (giveResult.success) {
                const giveEmbed = new Discord.EmbedBuilder()
                    .setColor('#00ff00')
                    .setTitle('💸 Transferencia Realizada')
                    .addFields(
                        { name: 'De', value: `${message.author.username}`, inline: true },
                        { name: 'Para', value: `${mentionedUser.username}`, inline: true },
                        { name: 'Cantidad', value: `${amountToGive}`, inline: true },
                        { name: 'Tu nuevo balance', value: `${giveResult.fromBalance}`, inline: true },
                        { name: `Balance de ${mentionedUser.username}`, value: `${giveResult.toBalance}`, inline: true }
                    )
                    .setTimestamp();
                
                message.reply({ embeds: [giveEmbed] });
                try { mentionedUser.send(`💰 ${message.author.username} te ha enviado ${amountToGive} dinero. Tu nuevo balance es: ${giveResult.toBalance}`); } catch (error) { }
            } else message.reply(`❌ ${giveResult.message}`);
            break;
            
        case '!admindar':
        case '!admingive':
            const adminIds = ['438147217702780939'];
            if (!adminIds.includes(message.author.id)) { message.reply('❌ No tienes permisos para usar este comando.'); return; }
            if (args.length < 3) { message.reply('❌ Uso: `!admindar <@usuario> <cantidad>`\nEjemplo: `!admindar @usuario 1000`'); return; }
            
            const adminMentionedUser = message.mentions.users.first();
            if (!adminMentionedUser) { message.reply('❌ Debes mencionar a un usuario válido.'); return; }
            if (adminMentionedUser.bot) { message.reply('❌ No puedes dar dinero a un bot.'); return; }
            
            const adminAmountToGive = parseFloat(args[2]);
            const adminGiveResult = giveMoney(message.author.id, adminMentionedUser.id, adminAmountToGive, true);
            
            if (adminGiveResult.success) {
                const adminGiveEmbed = new Discord.EmbedBuilder()
                    .setColor('#ff9900')
                    .setTitle('👑 Dinero Otorgado por Admin')
                    .addFields(
                        { name: 'Admin', value: `${message.author.username}`, inline: true },
                        { name: 'Usuario', value: `${adminMentionedUser.username}`, inline: true },
                        { name: 'Cantidad otorgada', value: `${adminAmountToGive}`, inline: true },
                        { name: `Nuevo balance de ${adminMentionedUser.username}`, value: `${adminGiveResult.toBalance}`, inline: false }
                    )
                    .setTimestamp();
                
                message.reply({ embeds: [adminGiveEmbed] });
                try { adminMentionedUser.send(`🎁 El administrador ${message.author.username} te ha otorgado ${adminAmountToGive} dinero. Tu nuevo balance es: ${adminGiveResult.toBalance}`); } catch (error) { }
            } else message.reply(`❌ ${adminGiveResult.message}`);
            break;
            
case '!resultado':
case '!setresult':
    if (args.length < 5) {
        message.reply(`❌ **Uso:** \`!resultado <ID_partido> <team1/draw/team2> <goles_equipo1> <goles_equipo2> [especiales]\`

**Especiales opcionales (separados por comas):**
corner, libre, chilena, cabeza, delantero, medio, defensa, arquero

**Ejemplo:** \`!resultado 1234567890 team1 2 1 corner,cabeza\`
**Ejemplo simple:** \`!resultado 1234567890 team1 2 1\``);
        return;
    }
    
    const resultMatchId = args[1], manualResult = args[2].toLowerCase(), goals1 = parseInt(args[3]), goals2 = parseInt(args[4]);
    const specialEvents = args[5] ? args[5].split(',').map(s => s.trim()) : [];
    
    // Crear objeto de resultados especiales
    const specialResults = {
        corner_goal: specialEvents.includes('corner'),
        free_kick_goal: specialEvents.includes('libre'),
        bicycle_kick_goal: specialEvents.includes('chilena'),
        header_goal: specialEvents.includes('cabeza'),
        striker_goal: specialEvents.includes('delantero'),
        midfielder_goal: specialEvents.includes('medio'),
        defender_goal: specialEvents.includes('defensa'),
        goalkeeper_goal: specialEvents.includes('arquero')
    };
    
    const manualResultResponse = setManualResult(resultMatchId, manualResult, goals1, goals2, specialResults);
    
    if (manualResultResponse.success) {
        const match = manualResultResponse.match;
        let winnerText = manualResultResponse.result === 'team1' ? match.team1.split(' (')[0] : manualResultResponse.result === 'team2' ? match.team2.split(' (')[0] : 'Empate';
        
        const specialEventsText = specialEvents.length > 0 ? 
            `\n**Eventos especiales:** ${specialEvents.join(', ')}` : '';
        
        const manualResultEmbed = new Discord.EmbedBuilder()
            .setColor('#9900ff')
            .setTitle('👤 Resultado Establecido Manualmente')
            .addFields(
                { name: 'Partido', value: `${getTeamEmoji(match.team1)} ${match.team1.split(' (')[0]} vs ${match.team2.split(' (')[0]} ${getTeamEmoji(match.team2)}`, inline: false },
                { name: 'Resultado Final', value: manualResultResponse.score + specialEventsText, inline: true },
                { name: 'Ganador', value: winnerText, inline: true },
                { name: 'Tipo', value: '👤 Resultado Manual', inline: true }
            );
        message.reply({ embeds: [manualResultEmbed] });
    } else {
        message.reply(`❌ ${manualResultResponse.message}`);
    }
    break;

        case '!misapuestas':
case '!mybets':
    const userBets = Object.values(bets).filter(bet => bet.userId === message.author.id);
    if (userBets.length === 0) { message.reply('❌ No tienes apuestas registradas.'); return; }
    
    const betsText = userBets.slice(-10).map(bet => {
        const match = matches[bet.matchId];
        if (!match) return '❌ Partido eliminado';
        
        let predictionText;
        
        // *** CORRECCIÓN PARA DISCORD ***
        if (bet.betType === 'exact_score' && bet.exactScore) {
            predictionText = `Exacto ${bet.exactScore.home}-${bet.exactScore.away}`;
        } else if (bet.betType === 'special' && bet.description) {
            predictionText = bet.description;
        } else if (bet.betType === 'special_combined' && bet.description) {
            predictionText = bet.description;
        } else if (bet.prediction) {
            predictionText = bet.prediction === 'team1' ? match.team1.split(' (')[0] : 
                           bet.prediction === 'team2' ? match.team2.split(' (')[0] : 'Empate';
        } else if (bet.description) {
            predictionText = bet.description;
        } else {
            predictionText = 'Apuesta especial';
        }
        
        const statusEmoji = bet.status === 'won' ? '✅' : bet.status === 'lost' ? '❌' : '⏳';
        return `${statusEmoji} **${match.team1.split(' (')[0]} vs ${match.team2.split(' (')[0]}**\nPredicción: ${predictionText} | Cuota: ${bet.odds} | Apostado: ${bet.amount}`;
    }).join('\n\n');
    
    const myBetsEmbed = new Discord.EmbedBuilder().setColor('#9900ff').setTitle('📋 Tus Últimas Apuestas').setDescription(betsText);
    message.reply({ embeds: [myBetsEmbed] });
    break;

        case '!eliminarmatch':
        case '!deletematch':
            if (args.length < 2) { message.reply('❌ Uso: `!eliminarmatch <ID_partido>`\nEjemplo: `!eliminarmatch 1234567890`'); return; }
            
            const deleteMatchId = args[1];
            const deleteResult = deleteMatch(deleteMatchId);
            
            if (deleteResult.success) {
                const deleteEmbed = new Discord.EmbedBuilder()
                    .setColor('#ff0000')
                    .setTitle('🗑️ Partido Eliminado')
                    .setDescription(deleteResult.message)
                    .addFields({ name: 'Partido eliminado', value: `${getTeamEmoji(deleteResult.match.team1)} ${deleteResult.match.team1.split(' (')[0]} vs ${deleteResult.match.team2.split(' (')[0]} ${getTeamEmoji(deleteResult.match.team2)}`, inline: false });
                message.reply({ embeds: [deleteEmbed] });
            } else message.reply(`❌ ${deleteResult.message}`);
            break;
            
        case '!limpiarpartidos':
        case '!clearmatches':
            const clearResult = deleteAllUpcomingMatches();
            
            if (clearResult.success) {
                const clearEmbed = new Discord.EmbedBuilder()
                    .setColor('#ff0000')
                    .setTitle('🗑️ Partidos Eliminados')
                    .setDescription(clearResult.message)
                    .addFields(
                        { name: 'Partidos eliminados', value: `${clearResult.deletedCount}`, inline: true },
                        { name: 'Apuestas canceladas', value: `${clearResult.betsReturned}`, inline: true },
                        { name: 'Dinero devuelto', value: `${clearResult.moneyReturned}`, inline: true }
                    );
                message.reply({ embeds: [clearEmbed] });
            } else message.reply(`❌ ${clearResult.message}`);
            break;
            
        case '!limpiarhistorial':
        case '!clearhistory':
            const historyResult = deleteFinishedMatches();
            
            if (historyResult.success) {
                const historyEmbed = new Discord.EmbedBuilder()
                    .setColor('#ff0000')
                    .setTitle('🗑️ Historial Limpiado')
                    .setDescription(historyResult.message)
                    .addFields({ name: 'Partidos eliminados del historial', value: `${historyResult.deletedCount}`, inline: true });
                message.reply({ embeds: [historyEmbed] });
            } else message.reply(`❌ ${historyResult.message}`);
            break;
            
        case '!actualizard1':
            message.reply('🔍 Obteniendo equipos de División 1...');
            const d1Data = await scrapeIOSoccerTeams('d1');
            if (d1Data && Object.keys(d1Data).length > 0) {
                teams = { ...teams, ...d1Data };
                saveData();
                
                const embed = new Discord.EmbedBuilder()
                    .setColor('#00ff00')
                    .setTitle('✅ División 1 Actualizada')
                    .setDescription(`Se obtuvieron ${Object.keys(d1Data).length} equipos de IOSoccer`)
                    .addFields({ name: 'Equipos obtenidos:', value: Object.keys(d1Data).slice(0, 8).map(name => name.replace(' (D1)', '')).join('\n') + (Object.keys(d1Data).length > 8 ? '\n...' : '') })
                    .setFooter({ text: 'Usa !equipos para ver todos los equipos' });
                message.reply({ embeds: [embed] });
            } else message.reply('❌ No se pudieron obtener datos de División 1. Verifica la conexión a internet.');
            break;

        case '!actualizard2':
            message.reply('🔍 Obteniendo equipos de División 2...');
            const d2Data = await scrapeIOSoccerTeams('d2');
            if (d2Data && Object.keys(d2Data).length > 0) {
                teams = { ...teams, ...d2Data };
                saveData();
                
                const embed = new Discord.EmbedBuilder()
                    .setColor('#00ff00')
                    .setTitle('✅ División 2 Actualizada')
                    .setDescription(`Se obtuvieron ${Object.keys(d2Data).length} equipos de IOSoccer`)
                    .addFields({ name: 'Equipos obtenidos:', value: Object.keys(d2Data).slice(0, 8).map(name => name.replace(' (D2)', '')).join('\n') + (Object.keys(d2Data).length > 8 ? '\n...' : '') })
                    .setFooter({ text: 'Usa !equipos para ver todos los equipos' });
                message.reply({ embeds: [embed] });
            } else message.reply('❌ No se pudieron obtener datos de División 2. Verifica la conexión a internet.');
            break;
            case '!actualizartorneo':
    if (args.length < 2) {
        const tournamentsText = Object.entries(TOURNAMENT_NAMES)
            .map(([code, name]) => `• \`${code}\` - ${name}`)
            .join('\n');
        
        message.reply(`❌ Uso: \`!actualizartorneo <código_torneo>\`

**Torneos disponibles:**
${tournamentsText}`);
        return;
    }
    
    const tournamentCode = args[1].toLowerCase();
    if (!TOURNAMENT_NAMES[tournamentCode]) {
        message.reply(`❌ Torneo "${tournamentCode}" no encontrado. Usa \`!actualizartorneo\` sin parámetros para ver la lista.`);
        return;
    }
    
    message.reply(`🔍 Obteniendo equipos de ${TOURNAMENT_NAMES[tournamentCode]}...`);
    const tournamentData = await scrapeIOSoccerTeams(tournamentCode);
    
    if (tournamentData && Object.keys(tournamentData).length > 0) {
        teams = { ...teams, ...tournamentData };
        saveData();
        
        const embed = new Discord.EmbedBuilder()
            .setColor('#00ff00')
            .setTitle(`✅ ${TOURNAMENT_NAMES[tournamentCode]} Actualizado`)
            .setDescription(`Se obtuvieron ${Object.keys(tournamentData).length} equipos de IOSoccer`)
            .addFields({ 
                name: 'Equipos obtenidos:', 
                value: Object.keys(tournamentData).slice(0, 8)
                    .map(name => name.replace(/ \([^)]+\)/, ''))
                    .join('\n') + (Object.keys(tournamentData).length > 8 ? '\n...' : '') 
            })
            .setFooter({ text: 'Usa !equipos para ver todos los equipos' });
        
        message.reply({ embeds: [embed] });
    } else {
        message.reply(`❌ No se pudieron obtener datos de ${TOURNAMENT_NAMES[tournamentCode]}. Verifica la conexión a internet.`);
    }
    break;
        case '!actualizartodo':
        case '!updateall':
            message.reply('🔍 Obteniendo todos los equipos de IOSoccer... Esto puede tomar unos segundos.');
            const allData = await scrapeAllLeagues();
            if (allData && Object.keys(allData).length > 0) {
                teams = { ...teams, ...allData };
                saveData();
                
                const d1Count = Object.keys(allData).filter(name => name.includes('(D1)')).length;
                const d2Count = Object.keys(allData).filter(name => name.includes('(D2)')).length;
                
                const embed = new Discord.EmbedBuilder()
                    .setColor('#00ff00')
                    .setTitle('✅ Todas las Ligas IOSoccer Actualizadas')
                    .addFields(
                        { name: 'División 1', value: `${d1Count} equipos`, inline: true },
                        { name: 'División 2', value: `${d2Count} equipos`, inline: true },
                        { name: 'Total', value: `${Object.keys(allData).length} equipos`, inline: true }
                    )
                    .setFooter({ text: 'Usa !equipos para ver la lista completa' });
                message.reply({ embeds: [embed] });
            } else message.reply('❌ No se pudieron obtener datos de IOSoccer. Verifica la conexión a internet.');
            break;

        case '!limpiarequipos':
            teams = {};
            saveData();
            message.reply('🗑️ Se eliminaron todos los equipos. Usa `!actualizartodo` para obtener equipos de IOSoccer.');
            break;

case '!help':
case '!ayuda':
    const helpEmbed = new Discord.EmbedBuilder()
        .setColor('#0099ff')
        .setTitle('🤖 Bot de Apuestas IOSoccer - Guía de Comandos')
        .setDescription('**¡Bienvenido al bot de apuestas con datos reales de IOSoccer Sudamérica!**\nAquí tienes todos los comandos organizados por categorías:')
        .addFields(
            { 
                name: '💰 **MI PERFIL Y DINERO**', 
                value: '`!balance` - Ver tu dinero, apuestas ganadas/perdidas y estadísticas\n`!misapuestas` - Ver tus últimas 10 apuestas con resultados\n`!dar @usuario <cantidad>` - Transferir dinero a otro jugador', 
                inline: false 
            },
            { 
                name: '🏆 **EQUIPOS Y TORNEOS**', 
                value: '`!equipos` - Ver todos los equipos organizados por torneo\n`!actualizartodo` - Actualizar equipos desde IOSoccer (todas las ligas)\n`!actualizartorneo <código>` - Actualizar torneo específico (d1, d2, maradei, etc.)', 
                inline: false 
            },
            { 
                name: '⚽ **PARTIDOS**', 
                value: '`!partidos` - Ver todos los partidos disponibles para apostar\n`!crearmatch "Equipo1" vs "Equipo2"` - Crear partido personalizado\n`!crearmatch "Boca" vs "River" d1` - Crear partido de torneo específico\n`!generarmatch` - Generar partido aleatorio automático', 
                inline: false 
            },
            { 
                name: '💵 **APUESTAS BÁSICAS**', 
                value: '`!apostar <ID> team1 <cantidad>` - Apostar por victoria del primer equipo\n`!apostar <ID> draw <cantidad>` - Apostar por empate\n`!apostar <ID> team2 <cantidad>` - Apostar por victoria del segundo equipo\n`!cuotas <ID>` - Ver todas las cuotas disponibles de un partido', 
                inline: false 
            },
            { 
                name: '🎯 **APUESTAS ESPECIALES**', 
                value: '`!apostarespecial <ID> exacto-2-1 <cantidad>` - Resultado exacto\n`!apostarespecial <ID> ambos-marcan <cantidad>` - Ambos equipos marcan\n`!apostarespecial <ID> mas-2-5 <cantidad>` - Más de 2.5 goles\n`!apostarespecial <ID> corner <cantidad>` - Habrá gol de córner\n`!apostarespecial <ID> chilena <cantidad>` - Habrá gol de chilena\n*Y muchos más tipos especiales...*', 
                inline: false 
            },
            { 
                name: '🎮 **RESULTADOS**', 
                value: '`!simular <ID>` - Simular automáticamente el resultado de un partido\n`!resultado <ID> team1 2 1` - Establecer resultado manual (solo admin)\n`!resultado <ID> team1 2 1 corner,cabeza` - Con eventos especiales', 
                inline: false 
            },
            { 
                name: '🏅 **CÓDIGOS DE TORNEOS**', 
                value: '**Ligas:** `d1` `d2` `d3`\n**Copas:** `maradei` `cv` `cd2` `cd3` `izoro` `izplata`\n*Ejemplo: !crearmatch "Racing" vs "Independiente" maradei*', 
                inline: false 
            },
            { 
                name: '🗑️ **ADMINISTRACIÓN** *(Solo Admin)*', 
                value: '`!admindar @usuario <cantidad>` - Dar dinero gratis\n`!eliminarmatch <ID>` - Eliminar partido específico\n`!limpiarpartidos` - Eliminar todos los partidos pendientes\n`!limpiarhistorial` - Limpiar partidos terminados', 
                inline: false 
            }
        )
        .setFooter({ 
            text: '💡 Tip: Los equipos y posiciones se actualizan automáticamente desde IOSoccer • Las copas eliminatorias no muestran forma WDL',
            iconURL: client.user.avatarURL()
        })
        .setTimestamp();
    
    message.reply({ embeds: [helpEmbed] });
    break;
    case '!cuotas':
case '!odds':
    if (args.length < 2) {
        message.reply('❌ Uso: `!cuotas <ID_partido>`\nEjemplo: `!cuotas 1234567890`');
        return;
    }
    
    const oddsMatchId = args[1];
    const oddsMatch = matches[oddsMatchId];
    if (!oddsMatch) {
        message.reply('❌ No existe un partido con ese ID.');
        return;
    }
    
    const exactScores = {
        '0-0': calculateExactScoreOdds(oddsMatch, { home: 0, away: 0 }),
        '1-0': calculateExactScoreOdds(oddsMatch, { home: 1, away: 0 }),
        '0-1': calculateExactScoreOdds(oddsMatch, { home: 0, away: 1 }),
        '1-1': calculateExactScoreOdds(oddsMatch, { home: 1, away: 1 }),
        '2-0': calculateExactScoreOdds(oddsMatch, { home: 2, away: 0 }),
        '0-2': calculateExactScoreOdds(oddsMatch, { home: 0, away: 2 }),
        '2-1': calculateExactScoreOdds(oddsMatch, { home: 2, away: 1 }),
        '1-2': calculateExactScoreOdds(oddsMatch, { home: 1, away: 2 }),
        '2-2': calculateExactScoreOdds(oddsMatch, { home: 2, away: 2 })
    };
    
    const specialOdds = {
        'Ambos marcan': calculateSpecialOdds(oddsMatch, 'both_teams_score'),
        'Más de 2.5 goles': calculateSpecialOdds(oddsMatch, 'total_goals_over_2_5'),
        'Menos de 2.5 goles': calculateSpecialOdds(oddsMatch, 'total_goals_under_2_5'),
        'Gol de córner': calculateSpecialOdds(oddsMatch, 'corner_goal'),
        'Gol de tiro libre': calculateSpecialOdds(oddsMatch, 'free_kick_goal'),
        'Gol de chilena': calculateSpecialOdds(oddsMatch, 'bicycle_kick_goal'),
        'Gol de cabeza': calculateSpecialOdds(oddsMatch, 'header_goal'),
        'Gol de delantero': calculateSpecialOdds(oddsMatch, 'striker_goal'),
        'Gol de mediocampista': calculateSpecialOdds(oddsMatch, 'midfielder_goal'),
        'Gol de defensa': calculateSpecialOdds(oddsMatch, 'defender_goal'),
        'Gol de arquero': calculateSpecialOdds(oddsMatch, 'goalkeeper_goal')
    };
    
    const exactScoreText = Object.entries(exactScores)
        .map(([score, odds]) => `${score}: ${odds}`)
        .join(' • ');
    
    const specialText = Object.entries(specialOdds)
        .map(([name, odds]) => `**${name}**: ${odds}`)
        .join('\n');
    
    const oddsEmbed = new Discord.EmbedBuilder()
        .setColor('#ff9900')
        .setTitle(`📊 Cuotas Completas - ${oddsMatch.team1.split(' (')[0]} vs ${oddsMatch.team2.split(' (')[0]}`)
        .addFields(
            { name: '⚽ Resultado', value: `**${oddsMatch.team1.split(' (')[0]}**: ${oddsMatch.odds.team1}\n**Empate**: ${oddsMatch.odds.draw}\n**${oddsMatch.team2.split(' (')[0]}**: ${oddsMatch.odds.team2}`, inline: false },
            { name: '🎯 Resultados Exactos', value: exactScoreText, inline: false },
            { name: '🏆 Apuestas Especiales', value: specialText, inline: false }
        )
        .setFooter({ text: 'Usa !apostarespecial para apostar en estos mercados' });
    
    message.reply({ embeds: [oddsEmbed] });
    break;

case '!apostarespecial':
case '!betspecial':
    if (args.length < 4) {
        message.reply(`❌ **Uso:** \`!apostarespecial <ID_partido> <tipo> <cantidad>\`

**Tipos disponibles:**
- \`exacto-X-Y\` - Resultado exacto (ej: exacto-2-1)
- \`ambos-marcan\` - Ambos equipos marcan
- \`mas-2-5\` - Más de 2.5 goles
- \`menos-2-5\` - Menos de 2.5 goles
- \`corner\` - Gol de córner
- \`libre\` - Gol de tiro libre
- \`chilena\` - Gol de chilena
- \`cabeza\` - Gol de cabeza
- \`delantero\` - Gol de delantero
- \`medio\` - Gol de mediocampista
- \`defensa\` - Gol de defensa
- \`arquero\` - Gol de arquero

**Ejemplo:** \`!apostarespecial 1234567890 exacto-2-1 100\``);
        return;
    }
    
    const specialMatchId = args[1];
    const specialType = args[2].toLowerCase();
    const specialAmount = parseFloat(args[3]);
    
    const specialMatch = matches[specialMatchId];
    if (!specialMatch) {
        message.reply('❌ No existe un partido con ese ID.');
        return;
    }
    
    if (specialMatch.status !== 'upcoming') {
        message.reply('❌ No puedes apostar en un partido que ya terminó.');
        return;
    }
    
    if (isNaN(specialAmount) || specialAmount <= 0) {
        message.reply('❌ La cantidad debe ser un número mayor a 0.');
        return;
    }
    
    if (userData[message.author.id].balance < specialAmount) {
        message.reply('❌ No tienes suficiente dinero para esta apuesta.');
        return;
    }
    
    let betOdds, betDescription, betData;
    
    if (specialType.startsWith('exacto-')) {
        const scoreParts = specialType.split('-');
        if (scoreParts.length !== 3) {
            message.reply('❌ Formato incorrecto para resultado exacto. Usa: exacto-X-Y (ej: exacto-2-1)');
            return;
        }
        
        const home = parseInt(scoreParts[1]);
        const away = parseInt(scoreParts[2]);
        
        if (isNaN(home) || isNaN(away) || home < 0 || away < 0) {
            message.reply('❌ Los goles deben ser números válidos (0 o mayor).');
            return;
        }
        
        betOdds = calculateExactScoreOdds(specialMatch, { home, away });
        betDescription = `Resultado exacto ${home}-${away}`;
        betData = { type: 'exact_score', exactScore: { home, away } };
    } else {
        const specialTypes = {
            'ambos-marcan': 'both_teams_score',
            'mas-2-5': 'total_goals_over_2_5',
            'menos-2-5': 'total_goals_under_2_5',
            'corner': 'corner_goal',
            'libre': 'free_kick_goal',
            'chilena': 'bicycle_kick_goal',
            'cabeza': 'header_goal',
            'delantero': 'striker_goal',
            'medio': 'midfielder_goal',
            'defensa': 'defender_goal',
            'arquero': 'goalkeeper_goal'
        };
        
        const specialNames = {
            'ambos-marcan': 'Ambos equipos marcan',
            'mas-2-5': 'Más de 2.5 goles',
            'menos-2-5': 'Menos de 2.5 goles',
            'corner': 'Gol de córner',
            'libre': 'Gol de tiro libre',
            'chilena': 'Gol de chilena',
            'cabeza': 'Gol de cabeza',
            'delantero': 'Gol de delantero',
            'medio': 'Gol de mediocampista',
            'defensa': 'Gol de defensa',
            'arquero': 'Gol de arquero'
        };
        
        if (!specialTypes[specialType]) {
            message.reply('❌ Tipo de apuesta especial no válido. Usa `!apostarespecial` sin parámetros para ver la lista.');
            return;
        }
        
        betOdds = calculateSpecialOdds(specialMatch, specialTypes[specialType]);
        betDescription = specialNames[specialType];
        betData = { type: 'special', specialType: specialTypes[specialType] };
    }
    
    const specialBetId = Date.now().toString() + Math.random().toString(36).substr(2, 5);
    
    bets[specialBetId] = {
    id: specialBetId,
        userId: message.author.id,
        matchId: specialMatchId,
        amount: specialAmount,
        odds: betOdds,
        status: 'pending',
        timestamp: new Date().toISOString(),
        betType: betData.type,
        description: betDescription,
        ...betData
    };
    
    userData[message.author.id].balance -= specialAmount;
    userData[message.author.id].totalBets++;
    
    if (!specialMatch.bets) specialMatch.bets = [];
    specialMatch.bets.push(specialBetId);
    
    saveData();
    broadcastUpdate('new-bet', { matchId: specialMatchId, userId: message.author.id, amount: specialAmount });
    
    const specialBetEmbed = new Discord.EmbedBuilder()
        .setColor('#9900ff')
        .setTitle('🎯 Apuesta Especial Realizada')
        .addFields(
            { name: 'Partido', value: `${specialMatch.team1.split(' (')[0]} vs ${specialMatch.team2.split(' (')[0]}`, inline: false },
            { name: 'Apuesta', value: betDescription, inline: true },
            { name: 'Cantidad apostada', value: `${specialAmount}`, inline: true },
            { name: 'Cuota', value: betOdds.toString(), inline: true },
            { name: 'Ganancia potencial', value: `${Math.round(specialAmount * betOdds)}`, inline: true },
            { name: 'Balance restante', value: `${userData[message.author.id].balance}`, inline: true }
        );
    
    message.reply({ embeds: [specialBetEmbed] });
    break;
    }
});

// Agregar después de loadData() en el ready event
client.on('ready', () => {
    console.log(`Bot conectado como ${client.user.tag}!`);
    loadData();
    
    // DEBUG: Mostrar usuarios cargados
    console.log(`📊 Usuarios cargados: ${Object.keys(userData).length}`);
    Object.entries(userData).forEach(([id, user]) => {
        console.log(`  - ${user.username || 'Usuario'}: Balance ${user.balance}`);
    });
    
    setInterval(() => {
        if (Object.keys(teams).length >= 2) {
            generateRandomMatches();
            console.log('Nuevo partido generado automáticamente');
        }
    }, 60 * 60 * 1000);
});

client.login(process.env.BOT_TOKEN);
