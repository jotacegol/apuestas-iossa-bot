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
// Agregar al inicio del archivo, después de los requires
const mongoose = require('mongoose');

// Esquemas de MongoDB
const userSchema = new mongoose.Schema({
    _id: String,
    username: String,
    discriminator: String,
    avatar: String,
    balance: { type: Number, default: 1000 },
    totalBets: { type: Number, default: 0 },
    wonBets: { type: Number, default: 0 },
    lostBets: { type: Number, default: 0 },
    totalWinnings: { type: Number, default: 0 }
});

const teamSchema = new mongoose.Schema({
    _id: String, // nombre completo del equipo
    position: Number,
    lastFiveMatches: String,
    league: String,
    tournament: String,
    originalName: String
});

const matchSchema = new mongoose.Schema({
    _id: String, // matchId
    team1: String,
    team2: String,
    odds: {
        team1: Number,
        draw: Number,
        team2: Number
    },
    matchTime: String,
    status: String,
    result: String,
    score: String,
    bets: [String],
    isCustom: Boolean,
    tournament: String
});

const betSchema = new mongoose.Schema({
    _id: String, // betId
    userId: String,
    matchId: String,
    prediction: String,
    amount: Number,
    odds: Number,
    status: String,
    timestamp: String,
    betType: String,
    description: String,
    exactScore: {
        home: Number,
        away: Number
    },
    specialType: String,
    specialBets: [mongoose.Schema.Types.Mixed]
});

const matchResultSchema = new mongoose.Schema({
    _id: String, // matchId
    result: String,
    score: String,
    timestamp: String,
    isManual: Boolean,
    setBy: String,
    specialResults: mongoose.Schema.Types.Mixed
});

// Modelos
const User = mongoose.model('User', userSchema);
const Team = mongoose.model('Team', teamSchema);
const Match = mongoose.model('Match', matchSchema);
const Bet = mongoose.model('Bet', betSchema);
const MatchResult = mongoose.model('MatchResult', matchResultSchema);
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
        
        // CORRECCIÓN: Crear descripción y datos correctamente
        betDescription = specialBets.map(type => specialNames[type]).join(' + ');
        betData = { 
            type: 'special_combined', 
            specialBets: specialBets.map(type => ({
                type: type,  // IMPORTANTE: usar 'type' en lugar de variables inconsistentes
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
    const { matchId, result, score1, score2, specialEvents = [] } = req.body;
    
    // Verificar que el usuario tiene permisos
    const adminIds = ['438147217702780939'];
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
    
    // CORRECCIÓN: Procesar correctamente los eventos especiales desde la web
    const specialResults = {};
    if (Array.isArray(specialEvents)) {
        specialEvents.forEach(event => {
            // Los eventos ya vienen con el nombre correcto desde el frontend
            specialResults[event] = true;
        });
    }
    
    console.log('🔍 Estableciendo resultado desde web:');
    console.log('   Marcador:', `${goals1}-${goals2}`);
    console.log('   Eventos especiales:', specialResults);
    
    // Establecer resultado
    match.status = 'finished';
    match.result = result;
    match.score = `${goals1}-${goals2}`;
    matchResults[matchId] = { 
        result, 
        score: `${goals1}-${goals2}`, 
        timestamp: new Date().toISOString(), 
        isManual: true,
        setBy: req.user.id,
        specialResults 
    };
    
    // Procesar apuestas con los eventos especiales
    processMatchBets(matchId, result, goals1, goals2, specialResults);
    saveData();
    
    // Notificar a todos los clientes conectados
    broadcastUpdate('match-result', { matchId, result, score: `${goals1}-${goals2}`, isManual: true, specialResults });
    
    res.json({ 
        success: true, 
        match: {
            id: match.id,
            team1: match.team1.split(' (')[0],
            team2: match.team2.split(' (')[0],
            result: match.result,
            score: match.score,
            isManual: true,
            specialResults
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
// API de Top Usuarios (Ranking de Millonarios)
app.get('/api/top-users', (req, res) => {
    try {
        // Obtener todos los usuarios y ordenarlos por balance
        const topUsers = Object.entries(userData)
            .map(([userId, user]) => ({
                id: userId,
                username: user.username || 'Usuario',
                discriminator: user.discriminator || '0000',
                avatar: user.avatar,
                balance: user.balance || 1000,
                totalBets: user.totalBets || 0,
                wonBets: user.wonBets || 0,
                lostBets: user.lostBets || 0,
                totalWinnings: user.totalWinnings || 0,
                winRate: user.totalBets > 0 ? (user.wonBets / user.totalBets * 100).toFixed(1) : 0
            }))
            .sort((a, b) => b.balance - a.balance) // Ordenar por balance descendente
            .slice(0, 10); // Solo los top 10

        console.log(`📊 Enviando ranking de ${topUsers.length} usuarios`);
        res.json(topUsers);
    } catch (error) {
        console.error('❌ Error obteniendo top usuarios:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// También agregar un endpoint para estadísticas generales mejoradas
app.get('/api/stats/general', (req, res) => {
    try {
        const totalUsers = Object.keys(userData).length;
        const totalMatches = Object.values(matches).filter(m => m.status === 'upcoming').length;
        const totalFinishedMatches = Object.values(matches).filter(m => m.status === 'finished').length;
        const totalBets = Object.keys(bets).length;
        const totalVolume = Object.values(bets).reduce((sum, bet) => sum + bet.amount, 0);
        const activeBets = Object.values(bets).filter(bet => bet.status === 'pending').length;
        
        // Calcular usuario con más balance
        const richestUser = Object.values(userData).reduce((richest, user) => {
            return (user.balance || 1000) > (richest.balance || 1000) ? user : richest;
        }, { balance: 0 });

        res.json({
            totalUsers,
            totalMatches,
            totalFinishedMatches,
            totalBets,
            totalVolume,
            activeBets,
            richestUserBalance: richestUser.balance || 1000,
            averageUserBalance: totalUsers > 0 ? Math.round(Object.values(userData).reduce((sum, user) => sum + (user.balance || 1000), 0) / totalUsers) : 1000
        });
    } catch (error) {
        console.error('❌ Error obteniendo estadísticas generales:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});
// Bot Discord
const client = new Discord.Client({ intents: [Discord.GatewayIntentBits.Guilds, Discord.GatewayIntentBits.GuildMessages, Discord.GatewayIntentBits.MessageContent] });

let userData = {}, teams = {}, matches = {}, bets = {}, matchResults = {};

// Función principal mejorada para calcular cuotas que considera el contexto del torneo
function calculateOdds(team1, team2, tournament = null) {
    const t1 = teams[team1], t2 = teams[team2];
    if (!t1 || !t2) return { team1: 2.0, draw: 3.0, team2: 2.0 };
    
    const t1League = t1.league || (team1.includes('(D1)') ? 'D1' : 'D2');
    const t2League = t2.league || (team2.includes('(D2)') ? 'D2' : 'D1');
    const t1Position = t1.position || 10;
    const t2Position = t2.position || 10;
    
    console.log(`🔍 Calculando cuotas: ${team1} (${t1League} pos.${t1Position}) vs ${team2} (${t2League} pos.${t2Position})`);
    
    // Si es un torneo de copa, usar cálculo especializado
    if (tournament && KNOCKOUT_TOURNAMENTS.includes(tournament)) {
        return calculateCupOdds(t1, t2, t1League, t2League, t1Position, t2Position, tournament);
    }
    
    // NUEVO SISTEMA: Cálculo de fuerza base más agresivo
    let t1BaseStrength = calculateNewTeamStrength(t1, t1League, t1Position);
    let t2BaseStrength = calculateNewTeamStrength(t2, t2League, t2Position);
    
    console.log(`💪 Fuerza base: ${team1}=${t1BaseStrength}, ${team2}=${t2BaseStrength}`);
    
    // CASOS EXTREMOS: Diferencias inter-liga con posiciones extremas
    if (t1League !== t2League) {
        const { t1Multiplier, t2Multiplier } = calculateExtremeInterLeagueMultipliers(
            t1League, t1Position, t2League, t2Position
        );
        
        t1BaseStrength *= t1Multiplier;
        t2BaseStrength *= t2Multiplier;
        
        console.log(`🚀 Multiplicadores inter-liga aplicados: t1=${t1Multiplier}, t2=${t2Multiplier}`);
        console.log(`💪 Fuerza final: ${team1}=${t1BaseStrength}, ${team2}=${t2BaseStrength}`);
    }
    
    // Aplicar bonificación por forma reciente (más conservadora)
    const t1FormBonus = calculateRealisticFormBonus(t1.lastFiveMatches || 'DDDDD');
    const t2FormBonus = calculateRealisticFormBonus(t2.lastFiveMatches || 'DDDDD');
    
    t1BaseStrength *= t1FormBonus;
    t2BaseStrength *= t2FormBonus;
    
    // Calcular probabilidades
    const total = t1BaseStrength + t2BaseStrength;
    const t1Prob = t1BaseStrength / total;
    const t2Prob = t2BaseStrength / total;
    
    // Probabilidad de empate ajustada según diferencia de nivel
    let drawProb = calculateRealisticDrawProbability(t1League, t2League, t1Position, t2Position, t1BaseStrength, t2BaseStrength);
    
    const adjustedT1Prob = t1Prob * (1 - drawProb);
    const adjustedT2Prob = t2Prob * (1 - drawProb);
    
    // Calcular cuotas con margen
    const margin = 0.08; // Margen de la casa más realista
    
    let team1Odds = Math.max(1.01, Math.min(50.0, (1 / adjustedT1Prob) * (1 - margin)));
    let team2Odds = Math.max(1.01, Math.min(50.0, (1 / adjustedT2Prob) * (1 - margin)));
    let drawOdds = Math.max(2.5, Math.min(20.0, (1 / drawProb) * (1 - margin)));
    
    // Aplicar límites finales para casos extremos
    const finalOdds = applyFinalOddsLimits(team1Odds, team2Odds, drawOdds, t1League, t1Position, t2League, t2Position);
    
    console.log(`🎯 Cuotas finales: ${team1}=${finalOdds.team1}, Empate=${finalOdds.draw}, ${team2}=${finalOdds.team2}`);
    
    return finalOdds;
}
function calculateNewTeamStrength(team, league, position) {
    let baseStrength = 100;
    
    // Bonificación/penalización por liga (más agresiva)
    if (league === 'D1') {
        baseStrength += 150; // D1 es MUY superior
    } else if (league === 'D2') {
        baseStrength += 50;  // D2 es mediocre
    } else if (league === 'D3') {
        baseStrength -= 50;  // D3 es inferior
    }
    
    // Bonificación/penalización por posición (más extrema)
    if (position === 1) {
        baseStrength *= (league === 'D1' ? 2.8 : league === 'D2' ? 2.2 : 1.8); // Líderes son MUY fuertes
    } else if (position === 2) {
        baseStrength *= (league === 'D1' ? 2.4 : league === 'D2' ? 1.9 : 1.6);
    } else if (position === 3) {
        baseStrength *= (league === 'D1' ? 2.1 : league === 'D2' ? 1.7 : 1.4);
    } else if (position <= 5) {
        baseStrength *= (league === 'D1' ? 1.8 : league === 'D2' ? 1.4 : 1.2); // Top 5
    } else if (position <= 8) {
        baseStrength *= (league === 'D1' ? 1.5 : league === 'D2' ? 1.1 : 1.0); // Top 8
    } else if (position <= 12) {
        baseStrength *= (league === 'D1' ? 1.2 : league === 'D2' ? 0.9 : 0.8); // Media tabla
    } else if (position <= 16) {
        baseStrength *= (league === 'D1' ? 1.0 : league === 'D2' ? 0.7 : 0.6); // Baja tabla
    } else {
        baseStrength *= (league === 'D1' ? 0.8 : league === 'D2' ? 0.5 : 0.4); // Últimos puestos son TERRIBLES
    }
    
    return Math.max(10, baseStrength); // Mínimo 10 para evitar divisiones por 0
}

function calculateExtremeInterLeagueMultipliers(t1League, t1Position, t2League, t2Position) {
    let t1Multiplier = 1.0;
    let t2Multiplier = 1.0;
    
    if (t1League === 'D1' && t2League === 'D2') {
        if (t1Position === 1) { // 1° D1
            if (t2Position >= 18) {
                t1Multiplier = 8.0;  // 1° D1 vs últimos D2 = súper favorito
                t2Multiplier = 0.15;
            } else if (t2Position >= 15) {
                t1Multiplier = 6.0;  // 1° D1 vs baja tabla D2
                t2Multiplier = 0.2;
            } else if (t2Position >= 10) {
                t1Multiplier = 4.5;  // 1° D1 vs media tabla D2
                t2Multiplier = 0.25;
            } else if (t2Position >= 5) {
                t1Multiplier = 3.5;  // 1° D1 vs top D2
                t2Multiplier = 0.35;
            } else {
                t1Multiplier = 2.8;  // 1° D1 vs top 5 D2
                t2Multiplier = 0.45;
            }
        } else if (t1Position <= 3) { // Top 3 D1
            if (t2Position >= 15) {
                t1Multiplier = 4.5;
                t2Multiplier = 0.25;
            } else if (t2Position >= 8) {
                t1Multiplier = 3.2;
                t2Multiplier = 0.35;
            } else {
                t1Multiplier = 2.5;
                t2Multiplier = 0.5;
            }
        } else if (t1Position <= 8) { // Top 8 D1
            if (t2Position >= 15) {
                t1Multiplier = 3.0;
                t2Multiplier = 0.4;
            } else if (t2Position >= 8) {
                t1Multiplier = 2.2;
                t2Multiplier = 0.55;
            } else {
                t1Multiplier = 1.8;
                t2Multiplier = 0.65;
            }
        } else { // Resto D1
            if (t2Position >= 15) {
                t1Multiplier = 2.0;
                t2Multiplier = 0.6;
            } else {
                t1Multiplier = 1.5;
                t2Multiplier = 0.75;
            }
        }
    } else if (t1League === 'D2' && t2League === 'D1') {
        // D2 vs D1: Invertir los multiplicadores
        const { t1Multiplier: temp1, t2Multiplier: temp2 } = calculateExtremeInterLeagueMultipliers(
            t2League, t2Position, t1League, t1Position
        );
        t1Multiplier = temp2;
        t2Multiplier = temp1;
    }
    
    return { t1Multiplier, t2Multiplier };
}

function calculateRealisticFormBonus(formString) {
    const wins = (formString.match(/W/g) || []).length;
    const losses = (formString.match(/L/g) || []).length;
    
    let bonus = 1.0;
    
    if (wins >= 4) bonus = 1.25;      // Muy buena racha
    else if (wins >= 3) bonus = 1.15; // Buena racha
    else if (wins >= 2) bonus = 1.08; // Forma decente
    else if (wins === 1) bonus = 1.02; // Forma regular
    
    if (losses >= 4) bonus *= 0.75;   // Muy mala racha
    else if (losses >= 3) bonus *= 0.85; // Mala racha
    else if (losses >= 2) bonus *= 0.92; // Forma irregular
    
    return Math.max(0.7, Math.min(1.3, bonus));
}

function calculateRealisticDrawProbability(t1League, t2League, t1Position, t2Position, t1Strength, t2Strength) {
    let baseDrawProb = 0.20;
    
    if (t1League !== t2League) {
        baseDrawProb = 0.12;
        
        const strengthRatio = Math.max(t1Strength, t2Strength) / Math.min(t1Strength, t2Strength);
        if (strengthRatio > 8) baseDrawProb = 0.08;
        else if (strengthRatio > 5) baseDrawProb = 0.10;
        else if (strengthRatio > 3) baseDrawProb = 0.12;
    } else {
        const avgPosition = (t1Position + t2Position) / 2;
        if (avgPosition <= 5) baseDrawProb = 0.18;
        else if (avgPosition <= 10) baseDrawProb = 0.22;
        else baseDrawProb = 0.25;
    }
    
    return Math.max(0.08, Math.min(0.25, baseDrawProb));
}

function applyFinalOddsLimits(team1Odds, team2Odds, drawOdds, t1League, t1Position, t2League, t2Position) {
    // Casos extremos: 1° D1 vs últimos D2
    if (t1League === 'D1' && t1Position === 1 && t2League === 'D2' && t2Position >= 18) {
        team1Odds = Math.min(team1Odds, 1.05);
        team2Odds = Math.max(team2Odds, 25.0);
        drawOdds = Math.max(drawOdds, 15.0);
    }
    else if (t1League === 'D1' && t1Position === 1 && t2League === 'D2' && t2Position >= 10) {
        team1Odds = Math.min(team1Odds, 1.10);
        team2Odds = Math.max(team2Odds, 15.0);
        drawOdds = Math.max(drawOdds, 12.0);
    }
    else if (t1League === 'D1' && t1Position <= 3 && t2League === 'D2' && t2Position >= 15) {
        team1Odds = Math.min(team1Odds, 1.20);
        team2Odds = Math.max(team2Odds, 12.0);
        drawOdds = Math.max(drawOdds, 10.0);
    }
    // Casos inversos (D2 vs D1)
    else if (t2League === 'D1' && t2Position === 1 && t1League === 'D2' && t1Position >= 18) {
        team2Odds = Math.min(team2Odds, 1.05);
        team1Odds = Math.max(team1Odds, 25.0);
        drawOdds = Math.max(drawOdds, 15.0);
    }
    else if (t2League === 'D1' && t2Position === 1 && t1League === 'D2' && t1Position >= 10) {
        team2Odds = Math.min(team2Odds, 1.10);
        team1Odds = Math.max(team1Odds, 15.0);
        drawOdds = Math.max(drawOdds, 12.0);
    }
    else if (t2League === 'D1' && t2Position <= 3 && t1League === 'D2' && t1Position >= 15) {
        team2Odds = Math.min(team2Odds, 1.20);
        team1Odds = Math.max(team1Odds, 12.0);
        drawOdds = Math.max(drawOdds, 10.0);
    }
    
    return {
        team1: Math.round(team1Odds * 100) / 100,
        draw: Math.round(drawOdds * 100) / 100,
        team2: Math.round(team2Odds * 100) / 100
    };
}

// Nueva función para calcular cuotas específicas de torneos de copa
function calculateCupOdds(t1, t2, t1League, t2League, t1Position, t2Position, tournament) {
    // Factores base según la liga de origen
    let t1BaseStrength = 100;
    let t2BaseStrength = 100;
    
    // Bonificación por liga (más agresiva para copas)
    if (t1League === 'D1') t1BaseStrength += 60;
    else if (t1League === 'D2') t1BaseStrength += 20;
    else if (t1League === 'D3') t1BaseStrength -= 30;
    
    if (t2League === 'D1') t2BaseStrength += 60;
    else if (t2League === 'D2') t2BaseStrength += 20;
    else if (t2League === 'D3') t2BaseStrength -= 30;
    
    // Bonificación/penalización por posición en liga (más agresiva para copas)
    const t1PositionModifier = calculateCupPositionModifier(t1Position, t1League);
    const t2PositionModifier = calculateCupPositionModifier(t2Position, t2League);
    
    t1BaseStrength *= t1PositionModifier;
    t2BaseStrength *= t2PositionModifier;
    
    // Bonificación por forma reciente (más importante en copas)
    const t1FormBonus = calculateFormBonus(t1.lastFiveMatches || 'DDDDD');
    const t2FormBonus = calculateFormBonus(t2.lastFiveMatches || 'DDDDD');
    
    t1BaseStrength *= t1FormBonus;
    t2BaseStrength *= t2FormBonus;
    
    // Aplicar factores específicos del torneo
    const tournamentFactor = getCupTournamentFactor(tournament, t1League, t2League);
    t1BaseStrength *= tournamentFactor.team1Multiplier;
    t2BaseStrength *= tournamentFactor.team2Multiplier;
    
    // Casos extremos: 1ro D1 vs equipos muy inferiores
    if (t1League === 'D1' && t1Position === 1) {
        if (t2League === 'D2' && t2Position >= 7) {
            t1BaseStrength *= 4.0; // Súper favorito
        } else if (t2League === 'D3' || (t2League === 'D2' && t2Position >= 15)) {
            t1BaseStrength *= 6.0; // Extremadamente favorito
        } else if (t2League === 'D2' && t2Position >= 4) {
            t1BaseStrength *= 2.5; // Muy favorito
        }
    }
    
    if (t2League === 'D1' && t2Position === 1) {
        if (t1League === 'D2' && t1Position >= 7) {
            t2BaseStrength *= 4.0;
        } else if (t1League === 'D3' || (t1League === 'D2' && t1Position >= 15)) {
            t2BaseStrength *= 6.0;
        } else if (t1League === 'D2' && t1Position >= 4) {
            t2BaseStrength *= 2.5;
        }
    }
    
    // Casos adicionales: Primeros 3 de D1 vs equipos medios/bajos de D2
    if (t1League === 'D1' && t1Position <= 3 && t2League === 'D2' && t2Position >= 8) {
        t1BaseStrength *= 2.8;
    }
    if (t2League === 'D1' && t2Position <= 3 && t1League === 'D2' && t1Position >= 8) {
        t2BaseStrength *= 2.8;
    }
    
    // Calcular probabilidades
    const total = t1BaseStrength + t2BaseStrength;
    const t1Prob = t1BaseStrength / total;
    const t2Prob = t2BaseStrength / total;
    
    // Probabilidad de empate más baja en copas eliminatorias
    let drawProb = 0.16;
    
    // Ajustar probabilidad de empate según la diferencia de nivel
    const strengthRatio = Math.max(t1BaseStrength, t2BaseStrength) / Math.min(t1BaseStrength, t2BaseStrength);
    if (strengthRatio > 5) drawProb = 0.10; // Muy pocos empates cuando hay gran diferencia
    else if (strengthRatio > 3) drawProb = 0.12;
    else if (strengthRatio > 2) drawProb = 0.14;
    
    const adjustedT1Prob = t1Prob * (1 - drawProb);
    const adjustedT2Prob = t2Prob * (1 - drawProb);
    
    // Calcular cuotas con margen más bajo para copas
    const margin = 0.03;
    
    let team1Odds = Math.max(1.05, Math.min(30.0, (1 / adjustedT1Prob) * (1 - margin)));
    let team2Odds = Math.max(1.05, Math.min(30.0, (1 / adjustedT2Prob) * (1 - margin)));
    let drawOdds = Math.max(3.2, Math.min(10.0, (1 / drawProb) * (1 - margin)));
    
    return {
        team1: Math.round(team1Odds * 100) / 100,
        draw: Math.round(drawOdds * 100) / 100,
        team2: Math.round(team2Odds * 100) / 100
    };
}

// Función para calcular modificador de posición específico para copas
function calculateCupPositionModifier(position, league) {
    let baseModifier = 1.0;
    
    if (league === 'D1') {
        if (position === 1) baseModifier = 3.2;      // Líder D1: súper favorito
        else if (position === 2) baseModifier = 2.6;  // 2do D1: muy favorito
        else if (position === 3) baseModifier = 2.2;  // 3ro D1: favorito
        else if (position <= 5) baseModifier = 1.8;   // Top 5 D1
        else if (position <= 8) baseModifier = 1.5;   // Top 8 D1
        else if (position <= 12) baseModifier = 1.2;  // Media tabla D1
        else if (position <= 16) baseModifier = 1.0;  // Baja tabla D1
        else baseModifier = 0.8;                      // Últimos D1
    } else if (league === 'D2') {
        if (position === 1) baseModifier = 2.0;       // Líder D2: favorito moderado
        else if (position === 2) baseModifier = 1.7;  // 2do D2
        else if (position === 3) baseModifier = 1.5;  // 3ro D2
        else if (position <= 5) baseModifier = 1.3;   // Top 5 D2
        else if (position <= 8) baseModifier = 1.0;   // Top 8 D2
        else if (position <= 12) baseModifier = 0.8;  // Media tabla D2
        else if (position <= 16) baseModifier = 0.6;  // Baja tabla D2
        else baseModifier = 0.4;                      // Últimos D2
    } else if (league === 'D3') {
        if (position === 1) baseModifier = 1.3;       // Líder D3
        else if (position <= 3) baseModifier = 1.0;   // Top 3 D3
        else if (position <= 8) baseModifier = 0.8;   // Media tabla D3
        else baseModifier = 0.6;                      // Resto D3
    }
    
    return baseModifier;
}

// Función para calcular bonificación por forma reciente
function calculateFormBonus(formString) {
    const wins = (formString.match(/W/g) || []).length;
    const losses = (formString.match(/L/g) || []).length;
    const draws = (formString.match(/D/g) || []).length;
    
    let bonus = 1.0;
    
    // Bonificación por victorias
    if (wins >= 4) bonus = 1.35;      // Racha excelente
    else if (wins >= 3) bonus = 1.25; // Buena racha
    else if (wins >= 2) bonus = 1.15; // Forma decente
    else if (wins === 1) bonus = 1.05; // Forma regular
    else bonus = 0.85; // Sin victorias recientes
    
    // Penalización por derrotas
    if (losses >= 4) bonus *= 0.65;   // Muy mala racha
    else if (losses >= 3) bonus *= 0.75; // Mala racha
    else if (losses >= 2) bonus *= 0.85; // Forma irregular
    
    // Bonificación pequeña por invicto
    if (losses === 0 && wins >= 2) bonus *= 1.1;
    
    return Math.max(0.5, Math.min(1.8, bonus)); // Limitar entre 0.5 y 1.8
}

// Función para obtener factor específico del torneo
function getCupTournamentFactor(tournament, t1League, t2League) {
    let team1Multiplier = 1.0;
    let team2Multiplier = 1.0;
    
    // Factores específicos por torneo
    switch (tournament) {
        case 'maradei': // Copa Maradei - torneo prestigioso, favorece a D1
            if (t1League === 'D1') team1Multiplier *= 1.25;
            if (t2League === 'D1') team2Multiplier *= 1.25;
            if (t1League === 'D2') team1Multiplier *= 0.9; // Ligera desventaja D2
            if (t2League === 'D2') team2Multiplier *= 0.9;
            break;
            
        case 'cv': // Copa ValencARc - torneo eliminatorio puro
            // Factor neutro, la forma y posición son más importantes
            break;
            
        case 'cd2': // Copa D2 - solo equipos D2
            // Equipos están en igualdad de condiciones por liga
            break;
            
        case 'cd3': // Copa D3 - solo equipos D3
            // Equipos están en igualdad de condiciones por liga
            break;
            
        case 'izoro': // Copa Intrazonal de Oro - favorece equipos top
            if (t1League === 'D1') team1Multiplier *= 1.15;
            if (t2League === 'D1') team2Multiplier *= 1.15;
            break;
            
        case 'izplata': // Copa Intrazonal de Plata - favorece D2
            if (t1League === 'D2') team1Multiplier *= 1.12;
            if (t2League === 'D2') team2Multiplier *= 1.12;
            break;
    }
    
    return { team1Multiplier, team2Multiplier };
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

    // Conectar a MongoDB
async function connectDB() {
    try {
        await mongoose.connect(process.env.MONGODB_URI);
        console.log('✅ Conectado a MongoDB');
        await loadData(); // Cargar datos después de conectar
    } catch (error) {
        console.error('❌ Error conectando a MongoDB:', error);
        process.exit(1);
    }
}

// NUEVA función loadData() para MongoDB
async function loadData() {
    try {
        console.log('📥 Cargando datos desde MongoDB...');
        
        // Cargar usuarios
        const users = await User.find({});
        userData = {};
        users.forEach(user => {
            userData[user._id] = {
                username: user.username,
                discriminator: user.discriminator,
                avatar: user.avatar,
                balance: user.balance,
                totalBets: user.totalBets,
                wonBets: user.wonBets,
                lostBets: user.lostBets,
                totalWinnings: user.totalWinnings
            };
        });
        
        // Cargar equipos
        const teamDocs = await Team.find({});
        teams = {};
        teamDocs.forEach(team => {
            teams[team._id] = {
                position: team.position,
                lastFiveMatches: team.lastFiveMatches,
                league: team.league,
                tournament: team.tournament,
                originalName: team.originalName
            };
        });
        
        // Cargar partidos
        const matchDocs = await Match.find({});
        matches = {};
        matchDocs.forEach(match => {
            matches[match._id] = {
                id: match._id,
                team1: match.team1,
                team2: match.team2,
                odds: match.odds,
                matchTime: match.matchTime,
                status: match.status,
                result: match.result,
                score: match.score,
                bets: match.bets,
                isCustom: match.isCustom,
                tournament: match.tournament
            };
        });
        
        // Cargar apuestas
        const betDocs = await Bet.find({});
        bets = {};
        betDocs.forEach(bet => {
            bets[bet._id] = {
                id: bet._id,
                userId: bet.userId,
                matchId: bet.matchId,
                prediction: bet.prediction,
                amount: bet.amount,
                odds: bet.odds,
                status: bet.status,
                timestamp: bet.timestamp,
                betType: bet.betType,
                description: bet.description,
                exactScore: bet.exactScore,
                specialType: bet.specialType,
                specialBets: bet.specialBets
            };
        });
        
        // Cargar resultados
        const resultDocs = await MatchResult.find({});
        matchResults = {};
        resultDocs.forEach(result => {
            matchResults[result._id] = {
                result: result.result,
                score: result.score,
                timestamp: result.timestamp,
                isManual: result.isManual,
                setBy: result.setBy,
                specialResults: result.specialResults
            };
        });
        
        console.log(`✅ Datos cargados: ${Object.keys(userData).length} usuarios, ${Object.keys(teams).length} equipos, ${Object.keys(matches).length} partidos`);
        
    } catch (error) {
        console.error('❌ Error cargando datos:', error);
    }
}

// NUEVA función saveData() para MongoDB
async function saveData() {
    try {
        // Guardar usuarios
        for (const [userId, user] of Object.entries(userData)) {
            await User.findByIdAndUpdate(userId, {
                username: user.username,
                discriminator: user.discriminator,
                avatar: user.avatar,
                balance: user.balance,
                totalBets: user.totalBets,
                wonBets: user.wonBets,
                lostBets: user.lostBets,
                totalWinnings: user.totalWinnings
            }, { upsert: true });
        }
        
        // Guardar equipos
        for (const [teamName, team] of Object.entries(teams)) {
            await Team.findByIdAndUpdate(teamName, {
                position: team.position,
                lastFiveMatches: team.lastFiveMatches,
                league: team.league,
                tournament: team.tournament,
                originalName: team.originalName
            }, { upsert: true });
        }
        
        // Guardar partidos
        for (const [matchId, match] of Object.entries(matches)) {
            await Match.findByIdAndUpdate(matchId, {
                team1: match.team1,
                team2: match.team2,
                odds: match.odds,
                matchTime: match.matchTime,
                status: match.status,
                result: match.result,
                score: match.score,
                bets: match.bets,
                isCustom: match.isCustom,
                tournament: match.tournament
            }, { upsert: true });
        }
        
        // Guardar apuestas
        for (const [betId, bet] of Object.entries(bets)) {
            await Bet.findByIdAndUpdate(betId, {
                userId: bet.userId,
                matchId: bet.matchId,
                prediction: bet.prediction,
                amount: bet.amount,
                odds: bet.odds,
                status: bet.status,
                timestamp: bet.timestamp,
                betType: bet.betType,
                description: bet.description,
                exactScore: bet.exactScore,
                specialType: bet.specialType,
                specialBets: bet.specialBets
            }, { upsert: true });
        }
        
        // Guardar resultados
        for (const [matchId, result] of Object.entries(matchResults)) {
            await MatchResult.findByIdAndUpdate(matchId, {
                result: result.result,
                score: result.score,
                timestamp: result.timestamp,
                isManual: result.isManual,
                setBy: result.setBy,
                specialResults: result.specialResults
            }, { upsert: true });
        }
        
    } catch (error) {
        console.error('❌ Error guardando datos:', error);
    }
}

    // NUEVA función initUser() mejorada
async function initUser(userId, username = null, discriminator = null, avatar = null) {
    try {
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
            
            // Guardar inmediatamente en MongoDB
            await User.findByIdAndUpdate(userId, userData[userId], { upsert: true });
            console.log(`👤 Nuevo usuario creado: ${username || 'Usuario'}`);
        } else {
            // Actualizar datos si ya existe
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
                await User.findByIdAndUpdate(userId, userData[userId], { upsert: true });
            }
        }
        
        return userData[userId];
    } catch (error) {
        console.error('❌ Error inicializando usuario:', error);
        return userData[userId] || { balance: 1000, totalBets: 0, wonBets: 0, lostBets: 0, totalWinnings: 0 };
    }
}

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
                
                // CORRECCIÓN: Validación más robusta
                if (teamName && teamName.length > 0 && !isNaN(position) && position > 0) {
                    scrapedTeams[`${teamName} (${league.toUpperCase()})`] = { 
                        position, 
                        lastFiveMatches, 
                        league: league.toUpperCase(), 
                        tournament: TOURNAMENT_NAMES[league],
                        originalName: teamName 
                    };
                } else {
                    console.log(`⚠️ Datos inválidos para fila ${index}: teamName="${teamName}", position="${position}"`);
                }
            } catch (error) { 
                console.log(`⚠️ Error procesando fila ${index} en ${league}:`, error.message); 
            }
        });
        
        // CORRECCIÓN: Verificar que obtuvimos al menos algunos equipos
        if (Object.keys(scrapedTeams).length === 0) {
            console.log(`⚠️ No se encontraron equipos en ${league}, posible cambio en la estructura del sitio`);
        }
        
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

// Actualizar la función createCustomMatch para pasar el torneo
// PASO 3: REEMPLAZAR createCustomMatch() por createCustomMatchImproved()
// ================================================================================
// BUSCAR la función createCustomMatch() y REEMPLAZAR por:

function createCustomMatch(team1Name, team2Name, tournament = null) {
    const team1 = findTeamByName(team1Name, tournament);
    const team2 = findTeamByName(team2Name, tournament);
    
    if (!team1) {
        let message = `No se encontró el equipo "${team1Name}".`;
        if (tournament) {
            message += ` en ${TOURNAMENT_NAMES[tournament] || tournament}.`;
        }
        
        // Sugerir equipos similares
        const suggestions = getTeamSuggestions(team1Name, 3, tournament);
        if (suggestions.length > 0) {
            message += '\n\n**¿Quisiste decir?**\n' + 
                suggestions.map(s => `• **${s.name}** (${s.tournament} - Pos. ${s.position})`).join('\n');
        }
        
        message += `\n\nUsa \`!equipos\` para ver la lista completa.`;
        return { success: false, message };
    }
    
    if (!team2) {
        let message = `No se encontró el equipo "${team2Name}".`;
        if (tournament) {
            message += ` en ${TOURNAMENT_NAMES[tournament] || tournament}.`;
        }
        
        const suggestions = getTeamSuggestions(team2Name, 3, tournament);
        if (suggestions.length > 0) {
            message += '\n\n**¿Quisiste decir?**\n' + 
                suggestions.map(s => `• **${s.name}** (${s.tournament} - Pos. ${s.position})`).join('\n');
        }
        
        message += `\n\nUsa \`!equipos\` para ver la lista completa.`;
        return { success: false, message };
    }
    
    if (team1.fullName === team2.fullName) {
        return { success: false, message: 'Un equipo no puede jugar contra sí mismo.' };
    }
    
    const matchId = Date.now().toString();
    
    // Calcular cuotas con el NUEVO sistema
    const odds = calculateOdds(team1.fullName, team2.fullName, tournament);
    
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
    
    console.log('🔍 setManualResult - Procesando con eventos especiales:', specialResults);
    
    processMatchBets(matchId, result, score1, score2, specialResults);
    saveData();
    return { success: true, match, result, score: `${score1}-${score2}` };
}

function processMatchBets(matchId, result, goals1 = null, goals2 = null, specialResults = {}) {
    const match = matches[matchId];
    if (!match.bets) return;
    
    console.log(`🔍 Procesando apuestas para partido ${matchId}:`);
    console.log(`   Resultado: ${result}, Marcador: ${goals1}-${goals2}`);
    console.log(`   Eventos especiales:`, specialResults);
    
    for (let betId of match.bets) {
        const bet = bets[betId];
        if (!bet) continue;
        
        let won = false;
        
        console.log(`🎯 Procesando apuesta ${betId}:`);
        console.log(`   Tipo: ${bet.betType || 'simple'}`);
        console.log(`   Descripción: ${bet.description || bet.prediction}`);
        
        if (bet.betType === 'exact_score' && goals1 !== null && goals2 !== null) {
            won = bet.exactScore.home === goals1 && bet.exactScore.away === goals2;
            console.log(`   Exacto ${bet.exactScore.home}-${bet.exactScore.away} vs ${goals1}-${goals2}: ${won ? 'GANÓ' : 'PERDIÓ'}`);
        } else if (bet.betType === 'special' && bet.specialType) {
            won = checkSpecialBets(bet.specialType, goals1, goals2, specialResults);
            console.log(`   Especial ${bet.specialType}: ${won ? 'GANÓ' : 'PERDIÓ'}`);
        } else if (bet.betType === 'special_combined' && bet.specialBets) {
            // CORRECCIÓN: Extraer correctamente los tipos de las apuestas especiales
            const specialTypes = bet.specialBets.map(item => item.type || item.specialType || item);
            won = checkSpecialBets(specialTypes, goals1, goals2, specialResults);
            console.log(`   Combinada especial: ${won ? 'GANÓ' : 'PERDIÓ'}`);
        } else {
            // Apuesta simple tradicional
            won = bet.prediction === result;
            console.log(`   Simple ${bet.prediction} vs ${result}: ${won ? 'GANÓ' : 'PERDIÓ'}`);
        }
        
        bet.status = won ? 'won' : 'lost';
        bet.result = result;
        
        if (won) {
            const winnings = bet.amount * bet.odds;
            userData[bet.userId].balance += winnings;
            userData[bet.userId].wonBets++;
            userData[bet.userId].totalWinnings += winnings;
            console.log(`   💰 Usuario ${bet.userId} ganó ${winnings}`);
        } else {
            userData[bet.userId].lostBets++;
            console.log(`   ❌ Usuario ${bet.userId} perdió ${bet.amount}`);
        }
    }
}

function checkSpecialBets(specialBets, goals1, goals2, specialResults) {
    // Si specialBets es un array (apuestas combinadas)
    if (Array.isArray(specialBets)) {
        for (const specialBet of specialBets) {
            // Obtener el tipo correcto del objeto
            const specialType = specialBet.type || specialBet.specialType || specialBet;
            let betWon = false;
            
            switch (specialType) {
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
                    betWon = specialResults[specialType] === true;
                    break;
            }
            
            if (!betWon) return false; // Si falla una, falla toda la apuesta
        }
        return true;
    }
    
    // Si specialBets es un string (caso de apuesta individual)
    const specialType = specialBets;
    switch (specialType) {
        case 'both_teams_score':
            return goals1 > 0 && goals2 > 0;
        case 'total_goals_over_2_5':
            return (goals1 + goals2) > 2.5;
        case 'total_goals_under_2_5':
            return (goals1 + goals2) < 2.5;
        case 'home_goals_over_1_5':
            return goals1 > 1.5;
        case 'away_goals_over_1_5':
            return goals2 > 1.5;
        default:
            // Para goles especiales, usar specialResults
            return specialResults[specialType] === true;
    }
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
function levenshteinDistance(str1, str2) {
    const matrix = [];
    
    for (let i = 0; i <= str2.length; i++) {
        matrix[i] = [i];
    }
    
    for (let j = 0; j <= str1.length; j++) {
        matrix[0][j] = j;
    }
    
    for (let i = 1; i <= str2.length; i++) {
        for (let j = 1; j <= str1.length; j++) {
            if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
                matrix[i][j] = matrix[i - 1][j - 1];
            } else {
                matrix[i][j] = Math.min(
                    matrix[i - 1][j - 1] + 1,
                    matrix[i][j - 1] + 1,
                    matrix[i - 1][j] + 1
                );
            }
        }
    }
    
    return matrix[str2.length][str1.length];
}

function getTeamDetailedStats(teamName) {
    const team = findTeamByName(teamName);
    if (!team) return null;
    
    const teamData = team.data;
    const stats = {
        name: team.fullName.replace(/ \([^)]+\)/, ''),
        league: teamData.league || 'CUSTOM',
        tournament: teamData.tournament || 'Custom',
        position: teamData.position || '?',
        form: teamData.lastFiveMatches || 'DDDDD',
        realStats: teamData.realStats || null
    };
    
    // Calcular estadísticas de forma
    const formResults = stats.form.split('');
    const wins = formResults.filter(r => r === 'W').length;
    const draws = formResults.filter(r => r === 'D').length;
    const losses = formResults.filter(r => r === 'L').length;
    
    stats.formAnalysis = {
        wins, draws, losses,
        points: wins * 3 + draws,
        percentage: ((wins * 3 + draws) / 15 * 100).toFixed(1)
    };
    
    return stats;
}

// Función para scrappear resultados de IOSoccer
async function scrapeIOSoccerResults(maxPages = 8) {
    const results = [];
    const baseUrl = 'https://iosoccer-sa.com/resultados/t15';
    
    try {
        console.log('🔍 Iniciando scraping de resultados...');
        
        for (let page = 1; page <= maxPages; page++) {
            console.log(`📄 Procesando página ${page}/${maxPages}...`);
            
            try {
                const url = `${baseUrl}?page=${page}`;
                const response = await axios.get(url, {
                    headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
                    timeout: 15000
                });
                
                const $ = cheerio.load(response.data);
                let pageResults = 0;
                
                // Buscar elementos de resultados - MÚLTIPLES SELECTORES
                $('tr, .match-row, .result-row').each((index, element) => {
                    try {
                        const $row = $(element);
                        
                        let team1 = '', team2 = '', score = '', date = '';
                        
                        // Método 1: Buscar por celdas de tabla
                        const cells = $row.find('td');
                        if (cells.length >= 3) {
                            // Buscar equipos en las primeras celdas
                            cells.each((i, cell) => {
                                const cellText = $(cell).text().trim();
                                
                                // Si contiene "vs" o "-", es probable que sean equipos
                                if (cellText.includes(' vs ') || cellText.includes(' - ')) {
                                    const parts = cellText.split(/ vs | - /);
                                    if (parts.length === 2) {
                                        team1 = parts[0].trim();
                                        team2 = parts[1].trim();
                                    }
                                }
                                
                                // Buscar marcador
                                const scoreMatch = cellText.match(/(\d+)\s*[-:]\s*(\d+)/);
                                if (scoreMatch && !score) {
                                    score = `${scoreMatch[1]}-${scoreMatch[2]}`;
                                }
                            });
                        }
                        
                        // Método 2: Buscar en todo el texto de la fila
                        if (!team1 || !team2 || !score) {
                            const rowText = $row.text();
                            
                            // Buscar marcador en formato X-Y
                            const scoreMatch = rowText.match(/(\d+)\s*[-:]\s*(\d+)/);
                            if (scoreMatch) {
                                score = `${scoreMatch[1]}-${scoreMatch[2]}`;
                                
                                // Intentar extraer equipos del contexto
                                const beforeScore = rowText.substring(0, scoreMatch.index).trim();
                                const afterScore = rowText.substring(scoreMatch.index + scoreMatch[0].length).trim();
                                
                                // Si hay texto antes y después del marcador, pueden ser los equipos
                                const words = beforeScore.split(/\s+/);
                                if (words.length >= 2) {
                                    team1 = words.slice(-2).join(' '); // Últimas 2 palabras antes del marcador
                                }
                                
                                const afterWords = afterScore.split(/\s+/);
                                if (afterWords.length >= 2) {
                                    team2 = afterWords.slice(0, 2).join(' '); // Primeras 2 palabras después del marcador
                                }
                            }
                        }
                        
                        // Validar y limpiar datos
                        if (team1 && team2 && score) {
                            // Limpiar nombres de equipos
                            team1 = team1.replace(/[^\w\s]/g, '').trim();
                            team2 = team2.replace(/[^\w\s]/g, '').trim();
                            
                            // Validar que no sean números o palabras muy cortas
                            if (team1.length > 2 && team2.length > 2 && 
                                !team1.match(/^\d+$/) && !team2.match(/^\d+$/) &&
                                team1 !== team2) {
                                
                                results.push({
                                    team1: team1.trim(),
                                    team2: team2.trim(),
                                    score: score.trim(),
                                    date: date.trim() || 'Sin fecha',
                                    page: page,
                                    source: 'iosoccer-sa'
                                });
                                pageResults++;
                            }
                        }
                    } catch (error) {
                        // Silenciar errores individuales
                    }
                });
                
                console.log(`✅ Página ${page}: ${pageResults} resultados encontrados`);
                
                // Pausa entre páginas
                if (page < maxPages) {
                    await new Promise(resolve => setTimeout(resolve, 2000));
                }
                
            } catch (error) {
                console.error(`❌ Error en página ${page}:`, error.message);
            }
        }
        
        console.log(`🎯 Scraping completado: ${results.length} resultados totales encontrados`);
        return results;
        
    } catch (error) {
        console.error('❌ Error general en scraping de resultados:', error.message);
        return results;
    }
}

function analyzeTeamPerformance(results) {
    const teamStats = {};
    
    results.forEach(result => {
        const { team1, team2, score } = result;
        const [goals1, goals2] = score.split('-').map(g => parseInt(g.trim()));
        
        if (isNaN(goals1) || isNaN(goals2)) return;
        
        // Inicializar estadísticas si no existen
        [team1, team2].forEach(teamName => {
            if (!teamStats[teamName]) {
                teamStats[teamName] = {
                    matches: 0, wins: 0, draws: 0, losses: 0,
                    goalsFor: 0, goalsAgainst: 0, lastResults: []
                };
            }
        });
        
        // Actualizar estadísticas
        teamStats[team1].matches++;
        teamStats[team2].matches++;
        teamStats[team1].goalsFor += goals1;
        teamStats[team1].goalsAgainst += goals2;
        teamStats[team2].goalsFor += goals2;
        teamStats[team2].goalsAgainst += goals1;
        
        // Determinar resultado
        if (goals1 > goals2) {
            teamStats[team1].wins++;
            teamStats[team2].losses++;
            teamStats[team1].lastResults.unshift('W');
            teamStats[team2].lastResults.unshift('L');
        } else if (goals1 < goals2) {
            teamStats[team1].losses++;
            teamStats[team2].wins++;
            teamStats[team1].lastResults.unshift('L');
            teamStats[team2].lastResults.unshift('W');
        } else {
            teamStats[team1].draws++;
            teamStats[team2].draws++;
            teamStats[team1].lastResults.unshift('D');
            teamStats[team2].lastResults.unshift('D');
        }
        
        // Mantener solo los últimos 5 resultados
        teamStats[team1].lastResults = teamStats[team1].lastResults.slice(0, 5);
        teamStats[team2].lastResults = teamStats[team2].lastResults.slice(0, 5);
    });
    
    return teamStats;
}

        function updateTeamsWithRealResults(teamStats) {
    let updatedCount = 0;
    
    Object.entries(teamStats).forEach(([teamName, stats]) => {
        const matchedTeam = findTeamByName(teamName);
        
        if (matchedTeam) {
            const currentTeamData = teams[matchedTeam.fullName];
            
            if (stats.lastResults.length >= 3) {
                const newForm = stats.lastResults.join('').padEnd(5, 'D').substring(0, 5);
                
                if (currentTeamData.lastFiveMatches !== newForm) {
                    console.log(`📊 Actualizando forma de ${matchedTeam.fullName}: ${currentTeamData.lastFiveMatches} → ${newForm}`);
                    currentTeamData.lastFiveMatches = newForm;
                    
                    // Guardar estadísticas adicionales
                    currentTeamData.realStats = {
                        matches: stats.matches,
                        wins: stats.wins,
                        draws: stats.draws,
                        losses: stats.losses,
                        goalsFor: stats.goalsFor,
                        goalsAgainst: stats.goalsAgainst,
                        goalDifference: stats.goalsFor - stats.goalsAgainst,
                        averageGoalsFor: (stats.goalsFor / stats.matches).toFixed(2),
                        averageGoalsAgainst: (stats.goalsAgainst / stats.matches).toFixed(2),
                        winRate: ((stats.wins / stats.matches) * 100).toFixed(1),
                        lastUpdated: new Date().toISOString()
                    };
                    
                    updatedCount++;
                }
            }
        } else {
            console.log(`⚠️ No se encontró coincidencia para: ${teamName}`);
        }
    });
    
    return updatedCount;
}
        function analyzeResultSurprises(results, teamStats) {
    const surprises = [];
    const bigWins = [];
    
    results.forEach(result => {
        const { team1, team2, score } = result;
        const [goals1, goals2] = score.split('-').map(g => parseInt(g.trim()));
        
        if (isNaN(goals1) || isNaN(goals2)) return;
        
        // Detectar goleadas (diferencia >= 4 goles)
        const goalDiff = Math.abs(goals1 - goals2);
        if (goalDiff >= 4) {
            const winner = goals1 > goals2 ? team1 : team2;
            const loser = goals1 > goals2 ? team2 : team1;
            
            bigWins.push({
                winner,
                loser,
                score,
                goalDifference: goalDiff,
                type: goalDiff >= 7 ? 'massacre' : goalDiff >= 5 ? 'thrashing' : 'beating'
            });
        }
        
        // Detectar sorpresas potenciales
        if (goalDiff >= 6) {
            surprises.push({
                match: `${team1} ${score} ${team2}`,
                type: 'potential_upset_or_expected',
                notes: `Diferencia de ${goalDiff} goles`
            });
        }
    });
    
    return { surprises, bigWins };
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
\`!crearmatch "Aimstar" vs "Deportivo Tarrito" maradei\` (Copa Maradei - cuotas ajustadas)

**Torneos disponibles:**
${tournamentsText}

**💡 Nota:** Los torneos de copa (maradei, cv, etc.) tienen cuotas especialmente ajustadas que consideran el contexto eliminatorio.`);
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
    
    const resultMatchId = args[1];
    const manualResult = args[2].toLowerCase();
    const goals1 = parseInt(args[3]);
    const goals2 = parseInt(args[4]);
    const specialEvents = args[5] ? args[5].split(',').map(s => s.trim()) : [];
    
    // CORRECCIÓN: Mapeo consistente con las funciones de validación
    const specialResults = {};
    specialEvents.forEach(event => {
        const eventLower = event.toLowerCase();
        switch(eventLower) {
            case 'corner':
                specialResults['corner_goal'] = true;
                break;
            case 'libre':
            case 'tiro-libre':
                specialResults['free_kick_goal'] = true;
                break;
            case 'chilena':
            case 'bicycle':
                specialResults['bicycle_kick_goal'] = true;
                break;
            case 'cabeza':
            case 'header':
                specialResults['header_goal'] = true;
                break;
            case 'delantero':
            case 'striker':
                specialResults['striker_goal'] = true;
                break;
            case 'medio':
            case 'mediocampista':
            case 'midfielder':
                specialResults['midfielder_goal'] = true;
                break;
            case 'defensa':
            case 'defender':
                specialResults['defender_goal'] = true;
                break;
            case 'arquero':
            case 'portero':
            case 'goalkeeper':
                specialResults['goalkeeper_goal'] = true;
                break;
            default:
                console.log(`⚠️ Evento especial no reconocido: ${event}`);
        }
    });
    
    const manualResultResponse = setManualResult(resultMatchId, manualResult, goals1, goals2, specialResults);
    
    if (manualResultResponse.success) {
        const match = manualResultResponse.match;
        let winnerText = manualResultResponse.result === 'team1' ? match.team1.split(' (')[0] : 
                        manualResultResponse.result === 'team2' ? match.team2.split(' (')[0] : 'Empate';
        
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
         case '!actualizar_resultados':
case '!updateresults':
    const adminIdsForResults = ['438147217702780939'];
    if (!adminIdsForResults.includes(message.author.id)) {
        message.reply('❌ No tienes permisos para usar este comando.');
        return;
    }
    
    message.reply('🔍 Iniciando actualización de resultados desde IOSoccer... Esto puede tomar unos minutos.');
    
    try {
        const results = await scrapeIOSoccerResults(8);
        
        if (results.length === 0) {
            message.reply('❌ No se pudieron obtener resultados. Verifica la conexión o la estructura del sitio.');
            return;
        }
        
        const teamStats = analyzeTeamPerformance(results);
        const updatedCount = updateTeamsWithRealResults(teamStats);
        const { surprises, bigWins } = analyzeResultSurprises(results, teamStats);
        
        saveData();
        
        const topScorers = bigWins.slice(0, 5).map(bw => 
            `• **${bw.winner}** ${bw.score} ${bw.loser} (${bw.goalDifference} goles de diferencia)`
        ).join('\n') || 'No se encontraron goleadas significativas';
        
        const resultEmbed = new Discord.EmbedBuilder()
            .setColor('#00ff00')
            .setTitle('✅ Resultados Actualizados desde IOSoccer')
            .addFields(
                { name: 'Resultados procesados', value: `${results.length}`, inline: true },
                { name: 'Equipos actualizados', value: `${updatedCount}`, inline: true },
                { name: 'Goleadas detectadas', value: `${bigWins.length}`, inline: true },
                { name: '🔥 Goleadas más destacadas', value: topScorers, inline: false }
            )
            .setFooter({ text: 'Los equipos ahora tienen forma reciente basada en resultados reales' })
            .setTimestamp();
        
        message.reply({ embeds: [resultEmbed] });
        
    } catch (error) {
        console.error('❌ Error actualizando resultados:', error);
        message.reply('❌ Error al actualizar resultados. Revisa los logs para más detalles.');
    }
    break;
        case '!equipo':
case '!teamstats':
    if (args.length < 2) {
        message.reply('❌ Uso: `!equipo <nombre_equipo>`\nEjemplo: `!equipo Aimstar`');
        return;
    }
    
    const teamQuery = args.slice(1).join(' ');
    const teamStats = getTeamDetailedStats(teamQuery);
    
    if (!teamStats) {
        const suggestions = getTeamSuggestions(teamQuery, 3);
        let suggestionText = `❌ No se encontró el equipo "${teamQuery}".`;
        
        if (suggestions.length > 0) {
            suggestionText += '\n\n**¿Quisiste decir?**\n' + 
                suggestions.map(s => `• **${s.name}** (${s.tournament} - Pos. ${s.position})`).join('\n');
        }
        
        message.reply(suggestionText);
        return;
    }
    
    let statsText = `**Liga:** ${teamStats.tournament}\n`;
    statsText += `**Posición:** ${teamStats.position}\n`;
    statsText += `**Forma reciente:** ${teamStats.form} (${teamStats.formAnalysis.wins}W-${teamStats.formAnalysis.draws}D-${teamStats.formAnalysis.losses}L)\n`;
    statsText += `**Puntos en últimos 5:** ${teamStats.formAnalysis.points}/15 (${teamStats.formAnalysis.percentage}%)\n`;
    
    if (teamStats.realStats) {
        statsText += `\n**📊 Estadísticas Reales:**\n`;
        statsText += `Partidos: ${teamStats.realStats.matches} | `;
        statsText += `Récord: ${teamStats.realStats.wins}W-${teamStats.realStats.draws}D-${teamStats.realStats.losses}L\n`;
        statsText += `Goles: ${teamStats.realStats.goalsFor} a favor, ${teamStats.realStats.goalsAgainst} en contra\n`;
        statsText += `Promedio: ${teamStats.realStats.averageGoalsFor} por partido\n`;
        statsText += `Efectividad: ${teamStats.realStats.winRate}%\n`;
        statsText += `*Última actualización: ${new Date(teamStats.realStats.lastUpdated).toLocaleDateString()}*`;
    }
    
    const teamEmbed = new Discord.EmbedBuilder()
        .setColor('#0099ff')
        .setTitle(`📊 ${teamStats.name}`)
        .setDescription(statsText)
        .setFooter({ text: 'Usa !actualizar_resultados para obtener estadísticas más precisas' });
    
    message.reply({ embeds: [teamEmbed] });
    break;
        case '!comparar':
case '!compare':
    if (args.length < 4 || !args.includes('vs')) {
        message.reply('❌ Uso: `!comparar <equipo1> vs <equipo2>`\nEjemplo: `!comparar "Aimstar" vs "Deportivo Tarrito"`');
        return;
    }
    
    const compareCommand = message.content.slice(command.length).trim();
    const compareVsIndex = compareCommand.toLowerCase().indexOf(' vs ');
    
    const compareTeam1Input = compareCommand.slice(0, compareVsIndex).trim().replace(/"/g, '');
    const compareTeam2Input = compareCommand.slice(compareVsIndex + 4).trim().replace(/"/g, '');
    
    const compareTeam1Stats = getTeamDetailedStats(compareTeam1Input);
    const compareTeam2Stats = getTeamDetailedStats(compareTeam2Input);
    
    if (!compareTeam1Stats || !compareTeam2Stats) {
        message.reply('❌ No se encontró uno de los equipos para comparar.');
        return;
    }
    
    // Calcular ventajas
    let advantages = [];
    
    if (compareTeam1Stats.position < compareTeam2Stats.position) {
        advantages.push(`📈 **${compareTeam1Stats.name}** está mejor posicionado (${compareTeam1Stats.position}° vs ${compareTeam2Stats.position}°)`);
    } else if (compareTeam2Stats.position < compareTeam1Stats.position) {
        advantages.push(`📈 **${compareTeam2Stats.name}** está mejor posicionado (${compareTeam2Stats.position}° vs ${compareTeam1Stats.position}°)`);
    }
    
    if (compareTeam1Stats.formAnalysis.points > compareTeam2Stats.formAnalysis.points) {
        advantages.push(`🔥 **${compareTeam1Stats.name}** tiene mejor forma reciente (${compareTeam1Stats.formAnalysis.points} vs ${compareTeam2Stats.formAnalysis.points} puntos)`);
    } else if (compareTeam2Stats.formAnalysis.points > compareTeam1Stats.formAnalysis.points) {
        advantages.push(`🔥 **${compareTeam2Stats.name}** tiene mejor forma reciente (${compareTeam2Stats.formAnalysis.points} vs ${compareTeam1Stats.formAnalysis.points} puntos)`);
    }
    
    if (compareTeam1Stats.league !== compareTeam2Stats.league) {
        if (compareTeam1Stats.league === 'D1' && compareTeam2Stats.league === 'D2') {
            advantages.push(`⭐ **${compareTeam1Stats.name}** juega en una liga superior (D1 vs D2)`);
        } else if (compareTeam2Stats.league === 'D1' && compareTeam1Stats.league === 'D2') {
            advantages.push(`⭐ **${compareTeam2Stats.name}** juega en una liga superior (D1 vs D2)`);
        }
    }
    
    const comparisonText = `**${compareTeam1Stats.name}** (${compareTeam1Stats.tournament})\n` +
        `Posición: ${compareTeam1Stats.position} | Forma: ${compareTeam1Stats.form} (${compareTeam1Stats.formAnalysis.points} pts)\n\n` +
        `**${compareTeam2Stats.name}** (${compareTeam2Stats.tournament})\n` +
        `Posición: ${compareTeam2Stats.position} | Forma: ${compareTeam2Stats.form} (${compareTeam2Stats.formAnalysis.points} pts)\n\n` +
        `**Análisis:**\n${advantages.join('\n') || 'Equipos muy parejos'}`;
    
    const compareEmbed = new Discord.EmbedBuilder()
        .setColor('#9900ff')
        .setTitle(`⚖️ Comparación de Equipos`)
        .setDescription(comparisonText)
        .setFooter({ text: 'Usa !crearmatch para crear un partido entre estos equipos' });
    
    message.reply({ embeds: [compareEmbed] });
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
client.on('ready', async () => {
    console.log(`Bot conectado como ${client.user.tag}!`);
    await connectDB(); // Conectar a MongoDB primero
});

client.login(process.env.BOT_TOKEN);
